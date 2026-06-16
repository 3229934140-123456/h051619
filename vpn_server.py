import sys
import threading
import time
import struct
import argparse

from tun_device import TunDevice, parse_ip_header
from crypto_handshake import Handshake
from packet_encap import TunnelPacket, PacketType, parse_handshake_packet
from tunnel_transport import TunnelTransport
from router import RouteTable, SystemRouteManager, IPAllocator


class VPNServer:
    """
    VPN 服务端

    架构:
    - 监听一个 UDP 端口, 接受多个客户端连接
    - 每个客户端有独立的加密会话和虚拟内网 IP
    - 服务端在 TUN 设备和各客户端之间转发 IP 数据包
    - 维护路由表, 根据目的 IP 决定发给哪个客户端

    数据流向 (客户端 A -> 客户端 B):
    1. 客户端 A 的应用发出 IP 包, 目的地是客户端 B 的虚拟 IP
    2. 客户端 A 的 OS 将包发给 TUN 设备
    3. 客户端 A 的 VPN 程序 read 到包, 加密后通过 UDP 发给服务端
    4. 服务端收到 UDP 包, 解密得到原始 IP 包
    5. 服务端查路由表, 发现目的 IP 属于客户端 B
    6. 服务端用客户端 B 的密钥加密 IP 包, 通过 UDP 发给客户端 B
    7. 客户端 B 的 VPN 程序收到 UDP 包, 解密得到原始 IP 包
    8. 客户端 B 的 VPN 程序将 IP 包 write 到 TUN 设备
    9. 客户端 B 的 OS 从 TUN 设备收到包, 递交给应用程序
    """

    def __init__(self, listen_host: str, listen_port: int,
                 tun_ip: str = "10.0.0.1", tun_netmask: str = "255.255.255.0",
                 client_network: str = "10.0.0.0", client_netmask: str = "255.255.255.0",
                 heartbeat_interval: int = None,
                 heartbeat_timeout: int = None):
        """
        初始化 VPN 服务端

        Args:
            listen_host: 监听地址
            listen_port: 监听端口
            tun_ip: TUN 设备的 IP (服务端在虚拟内网的 IP)
            tun_netmask: TUN 设备的子网掩码
            client_network: 客户端网段
            client_netmask: 客户端子网掩码
            heartbeat_interval: 心跳间隔(秒)
            heartbeat_timeout: 心跳超时(秒)
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.tun_ip = tun_ip
        self.tun_netmask = tun_netmask
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout

        self.tun = None
        self.transport = None
        self.route_table = RouteTable()
        self.ip_allocator = IPAllocator(client_network, client_netmask, exclude_ips=[tun_ip])
        self.route_manager = None

        self._running = False
        self._tun_thread = None

    def start(self):
        """启动 VPN 服务端"""
        print("[服务端] 正在启动...")

        self.tun = TunDevice(name="tun0", ip=self.tun_ip, netmask=self.tun_netmask)
        self.tun.open()

        self.route_manager = SystemRouteManager("tun0")

        self.transport = TunnelTransport(
            local_addr=(self.listen_host, self.listen_port),
            heartbeat_interval=self._heartbeat_interval,
            heartbeat_timeout=self._heartbeat_timeout,
        )
        self.transport.on_data_received = self._on_transport_data
        self.transport.on_peer_connected = self._on_peer_connected
        self.transport.on_peer_disconnected = self._on_peer_disconnected
        self.transport.start()

        self._running = True

        self._tun_thread = threading.Thread(target=self._tun_read_loop, daemon=True)
        self._tun_thread.start()

        print(f"[服务端] 启动完成, 监听 {self.listen_host}:{self.listen_port}")
        print(f"[服务端] 虚拟网段: {self.tun_ip}/{self.tun_netmask}")

    def stop(self):
        """停止 VPN 服务端"""
        self._running = False
        if self.transport:
            self.transport.stop()
        if self.route_manager:
            self.route_manager.cleanup()
        if self.tun:
            self.tun.close()
        print("[服务端] 已停止")

    def _on_peer_connected(self, peer_addr):
        """新客户端连接"""
        print(f"[服务端] 新客户端连接: {peer_addr}")

    def _on_peer_disconnected(self, peer_addr):
        """客户端断开"""
        print(f"[服务端] 客户端断开: {peer_addr}")
        self.ip_allocator.release(peer_addr)
        self.route_table.remove_peer_routes(peer_addr)

    def _on_transport_data(self, data: bytes, peer_addr):
        """
        处理从客户端收到的数据

        根据消息类型分别处理:
        - 握手消息: 执行握手协议
        - 数据消息: 解密后写入 TUN 设备或转发给其他客户端
        """
        pkt_type = TunnelPacket.get_packet_type(data)

        if pkt_type in (0x10, 0x11, 0x12):
            self._handle_handshake(data, peer_addr)
            return

        if not self.transport.is_handshake_done(peer_addr):
            print(f"[服务端] 收到未握手客户端的数据, 丢弃: {peer_addr}")
            return

        try:
            tunnel_pkt = self.transport.get_tunnel_packet(peer_addr)
            ip_packet = tunnel_pkt.unpack_data(data)
        except ValueError as e:
            print(f"[服务端] 解封装失败 ({peer_addr}): {e}")
            return

        src_ip, dst_ip, protocol = parse_ip_header(ip_packet)
        if not src_ip or not dst_ip:
            return

        client_ip = self.ip_allocator.get_ip(peer_addr)
        if client_ip and src_ip != client_ip:
            print(f"[服务端] 源 IP 不匹配, 可能是伪造: {src_ip} (期望 {client_ip})")
            return

        self._route_ip_packet(ip_packet, dst_ip, src_peer=peer_addr)

    def _handle_handshake(self, data: bytes, peer_addr):
        """
        处理握手消息

        服务端握手流程:
        1. 收到 ClientHello (客户端公钥)
        2. 生成自己的密钥对, 计算共享密钥
        3. 发送 ServerHello (服务端公钥)
        4. 派生会话密钥
        5. 发送 Finished 消息
        6. 收到客户端 Finished, 验证通过, 握手完成
        """
        try:
            msg_type, payload = parse_handshake_packet(data)
        except ValueError:
            return

        handshake = self.transport.get_handshake(peer_addr)

        if msg_type == 0x10:
            print(f"[握手] 收到 ClientHello 来自 {peer_addr}")

            server_hello = handshake.process_client_hello(data)
            handshake.derive_session_key()

            self.transport.send_to(server_hello, peer_addr)
            print(f"[握手] 发送 ServerHello 到 {peer_addr}")

            finished = handshake.create_finished()
            self.transport.send_to(finished, peer_addr)

        elif msg_type == 0x12:
            if handshake.verify_finished(data):
                print(f"[握手] 与 {peer_addr} 握手成功")

                self.transport.set_handshake_done(peer_addr, handshake.session)

                client_ip = self.ip_allocator.allocate(peer_addr)
                if client_ip:
                    self.transport.set_peer_tun_ip(peer_addr, client_ip)
                    self.route_table.add_host_route(client_ip, peer_addr)

                    self._send_ip_assignment(client_ip, peer_addr)
            else:
                print(f"[握手] 与 {peer_addr} 握手失败 (Finished 验证失败)")

    def _send_ip_assignment(self, client_ip: str, peer_addr):
        """向客户端发送分配的 IP 信息 (用一个特殊的数据包装载)"""
        ip_bytes = socket.inet_aton(client_ip)
        msg = b"IP_ASSIGN:" + ip_bytes

        tunnel_pkt = self.transport.get_tunnel_packet(peer_addr)
        packet = tunnel_pkt.pack_data(msg)
        self.transport.send_to(packet, peer_addr)
        print(f"[服务端] 向 {peer_addr} 分配 IP: {client_ip}")

    def _route_ip_packet(self, ip_packet: bytes, dst_ip: str, src_peer=None):
        """
        路由 IP 数据包

        判断数据包的目的地:
        - 如果目的 IP 是服务端自己: 写入 TUN 设备, 交给本机处理
        - 如果目的 IP 是某个客户端: 转发给对应的客户端
        - 如果目的 IP 是未知的: 写入 TUN 设备 (可能是要访问外部网络)
        """
        if dst_ip == self.tun_ip:
            if self.tun:
                self.tun.write(ip_packet)
            return

        next_hop = self.route_table.lookup(dst_ip)

        if next_hop:
            try:
                tunnel_pkt = self.transport.get_tunnel_packet(next_hop)
                packet = tunnel_pkt.pack_data(ip_packet)
                self.transport.send_to(packet, next_hop)
            except Exception as e:
                print(f"[服务端] 转发失败: {e}")
        else:
            if self.tun:
                self.tun.write(ip_packet)

    def _tun_read_loop(self):
        """
        TUN 设备读取循环

        持续从 TUN 设备读取 IP 包, 根据目的地址转发给对应客户端。
        这些包可能来自:
        - 服务端本机发往虚拟内网的数据包
        - 从物理网卡转发过来的包 (如果服务端配置了 NAT/转发)
        """
        while self._running:
            try:
                packet = self.tun.read()
                if not packet:
                    continue

                src_ip, dst_ip, protocol = parse_ip_header(packet)
                if not src_ip or not dst_ip:
                    continue

                self._route_ip_packet(packet, dst_ip, src_peer=None)

            except Exception as e:
                if self._running:
                    print(f"[服务端] TUN 读取错误: {e}")

    def get_client_status(self, peer_addr) -> dict:
        """获取指定客户端的连接状态"""
        info = self.transport._peers.get(peer_addr)
        if not info:
            return {"connected": False}

        client_ip = self.ip_allocator.get_ip(peer_addr)
        return {
            "connected": True,
            "peer_addr": peer_addr,
            "tun_ip": client_ip,
            "handshake_done": info.get("handshake_done", False),
            "last_seen": info.get("last_seen", 0),
        }

    def get_connected_clients(self) -> list:
        """获取所有已完成握手的客户端列表"""
        clients = []
        for addr in list(self.transport._peers.keys()):
            status = self.get_client_status(addr)
            if status["handshake_done"]:
                clients.append(status)
        return clients

    def wait_for_client(self, peer_addr=None, timeout: float = 15) -> dict:
        """
        等待客户端连接完成

        Args:
            peer_addr: 指定客户端地址, None 表示等待任意客户端
            timeout: 超时时间(秒)

        Returns:
            dict: 客户端状态, 超时返回 None
        """
        start = time.time()
        while time.time() - start < timeout:
            clients = self.get_connected_clients()
            if peer_addr:
                for c in clients:
                    if c["peer_addr"] == peer_addr:
                        return c
            else:
                if clients:
                    return clients[0]
            time.sleep(0.1)
        return None

    def get_tunnel_packet_by_ip(self, tun_ip: str):
        """根据虚拟 IP 获取对应的隧道数据包处理器"""
        addr = self.transport.get_peer_by_tun_ip(tun_ip)
        if not addr:
            return None
        return self.transport.get_tunnel_packet(addr)

    def disconnect_peer(self, peer_addr):
        """手动断开指定客户端 (用于测试)"""
        if peer_addr in self.transport._peers:
            print(f"[服务端] 手动断开客户端: {peer_addr}")
            client_ip = self.ip_allocator.get_ip(peer_addr)
            if client_ip:
                self.ip_allocator.release(peer_addr)
                self.route_table.remove_peer_routes(peer_addr)
            del self.transport._peers[peer_addr]

    def send_ip_packet(self, ip_packet: bytes, dst_tun_ip: str) -> bool:
        """
        向指定虚拟 IP 发送 IP 数据包 (用于测试)

        Args:
            ip_packet: 原始 IP 包
            dst_tun_ip: 目标虚拟 IP

        Returns:
            bool: 是否成功发送
        """
        next_hop = self.route_table.lookup(dst_tun_ip)
        if not next_hop:
            return False

        try:
            tunnel_pkt = self.transport.get_tunnel_packet(next_hop)
            packet = tunnel_pkt.pack_data(ip_packet)
            self.transport.send_to(packet, next_hop)
            return True
        except Exception as e:
            print(f"[服务端] 发送失败: {e}")
            return False

    def run_forever(self):
        """运行直到中断"""
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[服务端] 收到中断信号")
            self.stop()


import socket


def main():
    parser = argparse.ArgumentParser(description="VPN 服务端")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=5000, help="监听端口")
    parser.add_argument("--tun-ip", default="10.0.0.1", help="TUN 设备 IP")
    parser.add_argument("--tun-netmask", default="255.255.255.0", help="TUN 子网掩码")
    args = parser.parse_args()

    server = VPNServer(
        listen_host=args.host,
        listen_port=args.port,
        tun_ip=args.tun_ip,
        tun_netmask=args.tun_netmask,
        client_network=args.tun_ip.rsplit(".", 1)[0] + ".0",
        client_netmask=args.tun_netmask,
    )

    server.start()
    server.run_forever()


if __name__ == "__main__":
    main()
