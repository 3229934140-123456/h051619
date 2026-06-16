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
                 routes: list = None):
        """
        初始化 VPN 客户端

        Args:
            server_host: 服务端地址
            server_port: 服务端端口
            routes: 需要走 VPN 的网段列表, 如 [("10.0.0.0", "255.255.255.0")]
        """
        self.server_host = server_host
        self.server_port = server_port
        self.server_addr = (server_host, server_port)
        self.routes = routes or []

        self.tun = None
        self.transport = None
        self.handshake = Handshake()
        self.tunnel_pkt = TunnelPacket()
        self.route_manager = None

        self.tun_ip = None
        self.tun_netmask = "255.255.255.0"
        self._connected = False
        self._running = False
        self._tun_thread = None

    def start(self):
        """启动 VPN 客户端"""
        print("[客户端] 正在启动...")

        self.transport = TunnelTransport(local_addr=("0.0.0.0", 0))
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

        client_hello = self.handshake.create_client_hello()
        self.transport.send_to(client_hello, self.server_addr)
        print("[握手] 发送 ClientHello")

        timeout = 10
        start_time = time.time()

        while time.time() - start_time < timeout:
            time.sleep(0.1)

            if self.handshake.handshake_done and self.tun_ip:
                return True

        raise TimeoutError("握手超时")

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
        print("[握手] 收到 ServerHello")
        self.handshake.process_server_hello(data)

    def _handle_server_finished(self, data: bytes):
        """处理服务端 Finished"""
        if self.handshake.verify_finished(data):
            print("[握手] 服务端 Finished 验证通过")

            self.tunnel_pkt.set_crypto_session(self.handshake.session)
            self.transport.set_handshake_done(self.server_addr, self.handshake.session)

            finished = self.handshake.create_finished()
            self.transport.send_to(finished, self.server_addr)
            print("[握手] 发送客户端 Finished")

            self._connected = True
            print("[握手] 握手完成, 等待 IP 分配...")
        else:
            print("[握手] 服务端 Finished 验证失败")

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

        if self.tun:
            self.tun.write(ip_packet)

    def _handle_ip_assignment(self, data: bytes):
        """处理 IP 分配消息"""
        ip_bytes = data[11:15]
        ip_int = struct.unpack("!I", ip_bytes)[0]
        self.tun_ip = socket.inet_ntoa(struct.pack("!I", ip_int))

        print(f"[客户端] 获得虚拟 IP: {self.tun_ip}")

        self.tun = TunDevice(name="tun0", ip=self.tun_ip, netmask=self.tun_netmask)
        self.tun.open()

        self.route_manager = SystemRouteManager("tun0")
        for network, netmask in self.routes:
            self.route_manager.add_route(network, netmask)

        print("[客户端] TUN 设备和路由配置完成")

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
