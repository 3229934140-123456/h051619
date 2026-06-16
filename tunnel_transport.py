import socket
import threading
import time
import struct
from typing import Callable, Optional, Dict, Tuple

from crypto_handshake import Handshake, CryptoSession
from packet_encap import TunnelPacket, PacketType, build_handshake_packet, parse_handshake_packet


class TunnelTransport:
    """
    隧道传输层 - 基于 UDP 的可靠(尽力而为)传输

    为什么用 UDP 而不是 TCP:
    1. 更低的延迟: TCP 的拥塞控制和重传会增加延迟
    2. 避免 TCP-over-TCP 问题: 如果 VPN 本身用 TCP, 内部的 TCP 流量
       会经历两层 TCP 拥塞控制, 性能急剧下降 (称为 TCP meltdown)
    3. 灵活性: 可以自己实现需要的可靠性机制

    传输层职责:
    - 管理 UDP socket
    - 处理数据包的发送和接收
    - 维护心跳机制
    - 管理对端连接状态
    """

    HEARTBEAT_INTERVAL = 10
    HEARTBEAT_TIMEOUT = 30

    def __init__(self, local_addr: Tuple[str, int] = None):
        """
        初始化隧道传输

        Args:
            local_addr: 本地绑定地址 (host, port)
        """
        self.local_addr = local_addr
        self.sock = None
        self._running = False
        self._recv_thread = None
        self._heartbeat_thread = None
        self._lock = threading.Lock()

        self.on_data_received: Optional[Callable[[bytes, Tuple[str, int]], None]] = None
        self.on_peer_connected: Optional[Callable[[Tuple[str, int]], None]] = None
        self.on_peer_disconnected: Optional[Callable[[Tuple[str, int]], None]] = None

        self._peers: Dict[Tuple[str, int], dict] = {}

    def start(self):
        """启动传输层"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.local_addr:
            self.sock.bind(self.local_addr)
            print(f"[传输] 监听 UDP {self.local_addr[0]}:{self.local_addr[1]}")

        self._running = True

        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def stop(self):
        """停止传输层"""
        self._running = False
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_to(self, data: bytes, peer_addr: Tuple[str, int]):
        """
        向指定对端发送数据

        Args:
            data: 要发送的数据
            peer_addr: 对端地址 (host, port)
        """
        if not self.sock:
            return
        with self._lock:
            self.sock.sendto(data, peer_addr)

    def _recv_loop(self):
        """接收循环 - 持续接收 UDP 数据包"""
        buffer_size = 65535
        while self._running:
            try:
                data, addr = self.sock.recvfrom(buffer_size)
                self._handle_packet(data, addr)
            except socket.error:
                if not self._running:
                    break
            except Exception as e:
                print(f"[传输] 接收错误: {e}")

    def _handle_packet(self, data: bytes, addr: Tuple[str, int]):
        """
        处理收到的数据包

        根据数据包类型分发:
        - 握手消息: 交给握手处理器
        - 数据消息: 交给上层 (数据回调)
        - 心跳消息: 更新对端状态
        """
        is_new_peer = addr not in self._peers

        peer_info = self._get_peer_info(addr)
        peer_info["last_seen"] = time.time()

        if is_new_peer and self.on_peer_connected:
            self.on_peer_connected(addr)

        pkt_type = TunnelPacket.get_packet_type(data)

        if pkt_type in (PacketType.HEARTBEAT, PacketType.HEARTBEAT_ACK):
            self._handle_heartbeat(data, addr)
        elif pkt_type == PacketType.DATA:
            if self.on_data_received:
                self.on_data_received(data, addr)
        else:
            if self.on_data_received:
                self.on_data_received(data, addr)

    def _get_peer_info(self, addr: Tuple[str, int]) -> dict:
        """获取或创建对端信息"""
        if addr not in self._peers:
            self._peers[addr] = {
                "last_seen": time.time(),
                "tunnel_packet": TunnelPacket(),
                "handshake": None,
                "tun_ip": None,
            }
        return self._peers[addr]

    def _handle_heartbeat(self, data: bytes, addr: Tuple[str, int]):
        """处理心跳包"""
        peer_info = self._get_peer_info(addr)
        tunnel_pkt = peer_info["tunnel_packet"]

        try:
            is_ack, seq = tunnel_pkt.unpack_heartbeat(data)
            if not is_ack:
                ack_pkt = tunnel_pkt.pack_heartbeat(is_ack=True)
                self.send_to(ack_pkt, addr)
        except ValueError as e:
            print(f"[传输] 心跳处理失败 ({addr}): {e}")

    def _heartbeat_loop(self):
        """
        心跳循环

        功能:
        1. 定期向已连接的对端发送心跳包
        2. 检测超时的对端并清理

        心跳的重要性:
        - NAT 保活: 很多 NAT 设备会在一段时间无流量后回收端口映射,
          定期发送心跳可以维持映射, 确保对端能主动发数据过来
        - 存活检测: 检测对端是否还在线, 及时清理失效连接
        - 延迟测量: 可以通过心跳的往返时间估计链路延迟
        """
        while self._running:
            time.sleep(self.HEARTBEAT_INTERVAL)

            now = time.time()
            peers_to_remove = []

            for addr, info in self._peers.items():
                if info.get("handshake") and info["handshake"].handshake_done:
                    tunnel_pkt = info["tunnel_packet"]
                    try:
                        heartbeat = tunnel_pkt.pack_heartbeat(is_ack=False)
                        self.send_to(heartbeat, addr)
                    except Exception as e:
                        print(f"[传输] 发送心跳失败 ({addr}): {e}")

                if now - info["last_seen"] > self.HEARTBEAT_TIMEOUT:
                    peers_to_remove.append(addr)

            for addr in peers_to_remove:
                print(f"[传输] 对端超时: {addr}")
                if self.on_peer_disconnected:
                    self.on_peer_disconnected(addr)
                del self._peers[addr]

    def get_tunnel_packet(self, addr: Tuple[str, int]) -> TunnelPacket:
        """获取指定对端的隧道数据包处理器"""
        return self._get_peer_info(addr)["tunnel_packet"]

    def get_handshake(self, addr: Tuple[str, int]) -> Handshake:
        """获取指定对端的握手状态"""
        info = self._get_peer_info(addr)
        if not info["handshake"]:
            info["handshake"] = Handshake()
        return info["handshake"]

    def set_handshake_done(self, addr: Tuple[str, int], session: CryptoSession):
        """标记对端握手完成"""
        info = self._get_peer_info(addr)
        info["tunnel_packet"].set_crypto_session(session)
        info["handshake_done"] = True

    def is_handshake_done(self, addr: Tuple[str, int]) -> bool:
        """检查对端是否已完成握手"""
        info = self._peers.get(addr)
        if not info:
            return False
        return info.get("handshake_done", False)

    def set_peer_tun_ip(self, addr: Tuple[str, int], tun_ip: str):
        """设置对端的虚拟内网 IP"""
        info = self._get_peer_info(addr)
        info["tun_ip"] = tun_ip

    def get_peer_by_tun_ip(self, tun_ip: str) -> Optional[Tuple[str, int]]:
        """根据虚拟内网 IP 查找对端地址"""
        for addr, info in self._peers.items():
            if info.get("tun_ip") == tun_ip:
                return addr
        return None

    def get_all_peers(self) -> Dict[Tuple[str, int], dict]:
        """获取所有对端信息"""
        return self._peers.copy()
