import sys
import threading
import time
import struct
import socket
import argparse

from tun_device import TunDevice, parse_ip_header
from crypto_handshake import Handshake
from packet_encap import TunnelPacket, PacketType, parse_handshake_packet
from tunnel_transport import TunnelTransport
from router import SystemRouteManager


class ClientDeliveryRecord:
    """客户端数据包到达记录 (用于测试验证)"""

    def __init__(self):
        self._records = []
        self._lock = threading.Lock()
        self._event = threading.Event()

    def record(self, src_ip: str, dst_ip: str, packet: bytes = b""):
        """记录一次到达事件"""
        with self._lock:
            self._records.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "packet": packet,
                "time": time.time(),
            })
            self._event.set()

    def wait_for(self, predicate, timeout: float = 5.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                for r in self._records:
                    if predicate(r):
                        return r
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            self._event.clear()
            self._event.wait(min(0.1, remaining))
        with self._lock:
            for r in self._records:
                if predicate(r):
                    return r
        return None

    def clear(self):
        with self._lock:
            self._records.clear()
            self._event.clear()

    def get_all(self) -> list:
        with self._lock:
            return list(self._records)


class VPNClient:
    """
    VPN 客户端

    功能:
    - 连接到 VPN 服务端
    - 执行握手协议, 协商加密密钥
    - 获取服务端分配的虚拟内网 IP
    - 在 TUN 设备和服务端之间转发 IP 数据包

    数据流向:
    本机应用 -> TUN 设备 -> 本程序 -> 加密 -> UDP -> 服务端
    服务端 -> UDP -> 解密 -> 本程序 -> TUN 设备 -> 本机应用
    """

    def __init__(self, server_host: str, server_port: int,
                 routes: list = None,
                 heartbeat_interval: int = None,
                 heartbeat_timeout: int = None):
        """
        初始化 VPN 客户端

        Args:
            server_host: 服务端地址
            server_port: 服务端端口
            routes: 需要走 VPN 的网段列表, 如 [("10.0.0.0", "255.255.255.0")
            heartbeat_interval: 心跳间隔(秒)
            heartbeat_timeout: 心跳超时(秒)
        """
        self.server_host = server_host
        self.server_port = server_port
        self.server_addr = (server_host, server_port)
        self.routes = routes or []
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout

        self.tun = None
        self.transport = None
        self.handshake = Handshake()
        self.tunnel_pkt = TunnelPacket()
        self.route_manager = None
        self.delivery_log = ClientDeliveryRecord()

        self.tun_ip = None
        self.tun_netmask = "255.255.255.0"
        self._connected = False
        self._running = False
        self._tun_thread = None

        self._handshake_stage = "init"
        self._handshake_error = None

    def start(self):
        """启动 VPN 客户端"""
        print("[客户端] 正在启动...")

        self.transport = TunnelTransport(
            local_addr=("0.0.0.0", 0),
            heartbeat_interval=self._heartbeat_interval,
            heartbeat_timeout=self._heartbeat_timeout,
        )
        self.transport.on_data_received = self._on_transport_data
        self.transport.start()

        self._do_handshake()

        self._running = True

        self._tun_thread = threading.Thread(target=self._tun_read_loop, daemon=True)
        self._tun_thread.start()

        print("[客户端] 启动完成")
        if self.tun_ip:
            print(f"[客户端] 虚拟 IP: {self.tun_ip}")

    def stop(self):
        """停止 VPN 客户端"""
        self._running = False
        if self.route_manager:
            self.route_manager.cleanup()
        if self.tun:
            self.tun.close()
        if self.transport:
            self.transport.stop()
        print("[客户端] 已停止")

    def _do_handshake(self):
        """
        执行握手协议

        客户端握手流程:
        1. 生成密钥对, 发送 ClientHello (带公钥)
        2. 等待 ServerHello, 获取服务端公钥
        3. 计算共享密钥, 派生会话密钥
        4. 等待服务端 Finished 消息
        5. 验证服务端 Finished
        6. 发送客户端 Finished
        7. 握手完成, 等待 IP 分配
        """
        print(f"[握手] 正在连接服务端 {self.server_addr}...")

        self._handshake_stage = "client_hello"
        client_hello = self.handshake.create_client_hello()
        self.transport.send_to(client_hello, self.server_addr)
        print("[握手] [1/5] 发送 ClientHello, 等待 ServerHello...")

        timeout = 15
        start_time = time.time()

        while time.time() - start_time < timeout:
            time.sleep(0.1)

            if self._handshake_error:
                raise RuntimeError(f"握手失败: {self._handshake_error}")

            if self._connected and self.tun_ip and self.tun and self.tun.get_config()["is_up"]:
                print("[握手] [完成] 握手成功, 已获得虚拟 IP 并完成配置")
                return True

        stage_desc = {
            "init": "初始化",
            "client_hello": "等待 ServerHello",
            "server_hello": "等待服务端 Finished",
            "server_finished": "等待 IP 分配",
            "ip_assigned": "配置 TUN 设备和路由",
            "done": "已完成",
        }
        desc = stage_desc.get(self._handshake_stage, self._handshake_stage)
        raise TimeoutError(f"握手超时 (当前阶段: {desc}), 请检查服务端是否启动或网络是否连通")

    def _on_transport_data(self, data: bytes, peer_addr):
        """处理从服务端收到的数据"""
        if peer_addr != self.server_addr:
            return

        pkt_type = TunnelPacket.get_packet_type(data)

        if pkt_type == 0x11:
            self._handle_server_hello(data)
        elif pkt_type == 0x12:
            self._handle_server_finished(data)
        elif pkt_type == PacketType.DATA:
            self._handle_data_packet(data)

    def _handle_server_hello(self, data: bytes):
        """处理 ServerHello"""
        print("[握手] [2/5] 收到 ServerHello, 计算共享密钥并派生会话密钥...")
        self._handshake_stage = "server_hello"
        try:
            self.handshake.process_server_hello(data)
            print("[握手] [2/5] 会话密钥派生完成, 等待服务端 Finished...")
        except Exception as e:
            self._handshake_error = f"ServerHello 处理失败: {e}"
            print(f"[握手] 错误: {self._handshake_error}")

    def _handle_server_finished(self, data: bytes):
        """处理服务端 Finished"""
        self._handshake_stage = "server_finished"
        if self.handshake.verify_finished(data):
            print("[握手] [3/5] 服务端 Finished 验证通过")

            self.tunnel_pkt.set_crypto_session(self.handshake.session)
            self.transport.set_handshake_done(self.server_addr, self.handshake.session)

            finished = self.handshake.create_finished()
            self.transport.send_to(finished, self.server_addr)
            print("[握手] [4/5] 发送客户端 Finished")

            self._connected = True
            print("[握手] [4/5] 加密通道建立完成, 等待 IP 分配...")
        else:
            self._handshake_error = "服务端 Finished 验证失败, 可能 PSK 不匹配"
            print(f"[握手] 错误: {self._handshake_error}")

    def _handle_data_packet(self, data: bytes):
        """处理数据消息"""
        try:
            ip_packet = self.tunnel_pkt.unpack_data(data)
        except ValueError as e:
            print(f"[客户端] 解封装失败: {e}")
            return

        if ip_packet.startswith(b"IP_ASSIGN:"):
            self._handle_ip_assignment(ip_packet)
            return

        src_ip, dst_ip, _ = parse_ip_header(ip_packet)
        self.delivery_log.record(src_ip or "?", dst_ip or "?", ip_packet)

        if self.tun:
            self.tun.write(ip_packet)

    def _handle_ip_assignment(self, data: bytes):
        """处理 IP 分配消息"""
        self._handshake_stage = "ip_assigned"
        prefix = b"IP_ASSIGN:"
        if not data.startswith(prefix):
            self._handshake_error = f"IP 分配消息格式错误: 缺少前缀 {prefix!r}"
            print(f"[客户端] 错误: {self._handshake_error}")
            return
        ip_bytes = data[len(prefix):len(prefix) + 4]
        if len(ip_bytes) < 4:
            self._handshake_error = f"IP 分配消息格式错误: 期望 4 字节 IP, 实际 {len(ip_bytes)} 字节"
            print(f"[客户端] 错误: {self._handshake_error}")
            return
        self.tun_ip = socket.inet_ntoa(ip_bytes)

        print(f"[握手] [5/5] 获得虚拟 IP: {self.tun_ip}")

        print(f"[客户端] 正在创建 TUN 设备 {self.tun_ip}/{self.tun_netmask}...")
        self.tun = TunDevice(name="tun0", ip=self.tun_ip, netmask=self.tun_netmask)
        self.tun.open()

        print(f"[客户端] 正在配置路由表 ({len(self.routes)} 条路由)...")
        self.route_manager = SystemRouteManager("tun0")
        for network, netmask in self.routes:
            self.route_manager.add_route(network, netmask)

        self._handshake_stage = "done"
        print("[客户端] ✅ 已连接! 虚拟 IP:", self.tun_ip)
        print(f"[客户端]    - TUN 设备: {self.tun.name}")
        print(f"[客户端]    - 服务端: {self.server_host}:{self.server_port}")
        print(f"[客户端]    - 路由网段: {', '.join([f'{n}/{m}' for n,m in self.routes])}")

    def get_status(self) -> dict:
        """获取客户端状态"""
        return {
            "connected": self._connected,
            "tun_ip": self.tun_ip,
            "handshake_stage": self._handshake_stage,
            "handshake_done": self.handshake.handshake_done,
            "server_addr": self.server_addr,
            "tun_config": self.tun.get_config() if self.tun else None,
            "routes": self.route_manager.added_routes if self.route_manager else [],
        }

    def wait_for_connection(self, timeout: float = 15) -> bool:
        """等待连接建立完成"""
        start = time.time()
        while time.time() - start < timeout:
            if self._connected and self.tun_ip and self.tun:
                return True
            if self._handshake_error:
                return False
            time.sleep(0.1)
        return False

    def _tun_read_loop(self):
        """TUN 设备读取循环 - 读取本机发出的包, 加密后发给服务端"""
        while self._running:
            if not self.tun or not self._connected:
                time.sleep(0.1)
                continue

            try:
                packet = self.tun.read()
                if not packet:
                    continue

                encrypted = self.tunnel_pkt.pack_data(packet)
                self.transport.send_to(encrypted, self.server_addr)

            except Exception as e:
                if self._running:
                    print(f"[客户端] TUN 读取错误: {e}")

    def run_forever(self):
        """运行直到中断"""
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[客户端] 收到中断信号")
            self.stop()


def main():
    parser = argparse.ArgumentParser(description="VPN 客户端")
    parser.add_argument("--server", required=True, help="服务端地址")
    parser.add_argument("--port", type=int, default=5000, help="服务端端口")
    parser.add_argument("--route", action="append", default=[],
                        help="走 VPN 的网段, 格式: 网络/掩码, 可多次指定")
    args = parser.parse_args()

    routes = []
    for r in args.route:
        if "/" in r:
            network, prefix = r.split("/")
            prefix = int(prefix)
            mask = []
            for i in range(4):
                n = min(max(prefix - i * 8, 0), 8)
                mask.append(str(256 - 2 ** (8 - n)) if n < 8 else "255")
            netmask = ".".join(mask)
            routes.append((network, netmask))
        else:
            routes.append((r, "255.255.255.255"))

    if not routes:
        routes.append(("10.0.0.0", "255.255.255.0"))

    client = VPNClient(
        server_host=args.server,
        server_port=args.port,
        routes=routes,
    )

    client.start()
    client.run_forever()


if __name__ == "__main__":
    main()
