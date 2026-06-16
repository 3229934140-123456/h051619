import struct
import os
from crypto_handshake import CryptoSession, ReplayProtector
from protocol_constants import PacketType


class TunnelPacket:
    """
    隧道数据包封装/解封装

    隧道协议格式 (总览):
    +--------+----------+---------+--------------------------+
    |  类型  |  序列号  |  Nonce  |   加密负载 + 认证标签     |
    | 1字节  |  8字节   | 12字节  |       变长 + 16字节       |
    +--------+----------+---------+--------------------------+

    各字段说明:
    - 类型 (Type): 1字节, 标识消息类型 (数据/心跳/握手等)
    - 序列号 (Sequence): 8字节, 单调递增, 用于防重放攻击
    - Nonce: 12字节, 每次加密使用不同的随机数, AES-GCM 所需
    - 加密负载: 原始 IP 包被 AES-GCM 加密后的密文
    - 认证标签: 16字节, AES-GCM 自动生成, 用于验证完整性和真实性

    为什么这样设计:
    1. 类型字段在最前面且不加密, 便于快速判断消息类型
    2. 序列号和类型一起作为 AEAD 的附加数据 (AD), 它们不加密但被认证保护
       防止攻击者篡改消息类型或重排序数据包
    3. Nonce 随机生成, 确保相同明文每次加密结果不同
    4. 认证标签在最后, 解密时验证, 失败则直接丢弃
    """

    HEADER_SIZE = 1 + 8 + 12
    AUTH_TAG_SIZE = 16

    def __init__(self, crypto_session: CryptoSession = None):
        self.crypto = crypto_session
        self.tx_replay = ReplayProtector()
        self.rx_replay = ReplayProtector()

    def set_crypto_session(self, session: CryptoSession):
        self.crypto = session

    def pack_data(self, ip_packet: bytes) -> bytes:
        """
        封装 IP 数据包为隧道数据包

        流程:
        1. 生成递增的序列号 (防重放)
        2. 生成随机 Nonce
        3. 构造附加数据 (类型 + 序列号), 这些数据不加密但被认证保护
        4. 使用 AES-GCM 加密 IP 包, 同时认证附加数据
        5. 组合成完整的隧道数据包

        Args:
            ip_packet: 原始 IP 数据包

        Returns:
            bytes: 完整的隧道数据包
        """
        if not self.crypto:
            raise RuntimeError("加密会话未初始化, 请先完成握手")

        seq = self.tx_replay.next_sequence()
        nonce = os.urandom(12)

        msg_type = PacketType.DATA
        header = struct.pack("!BQ", msg_type, seq) + nonce
        ad = struct.pack("!BQ", msg_type, seq)

        ciphertext_with_tag = self.crypto.encrypt(ip_packet, nonce, ad)

        return header + ciphertext_with_tag

    def unpack_data(self, tunnel_packet: bytes) -> bytes:
        """
        解封装隧道数据包, 还原 IP 包

        流程:
        1. 解析头部: 类型、序列号、Nonce
        2. 检查序列号 (防重放)
        3. 构造附加数据
        4. 使用 AES-GCM 解密并验证认证标签
        5. 返回原始 IP 包

        Args:
            tunnel_packet: 隧道数据包

        Returns:
            bytes: 原始 IP 数据包

        Raises:
            ValueError: 数据包无效或认证失败
        """
        if not self.crypto:
            raise RuntimeError("加密会话未初始化")

        if len(tunnel_packet) < self.HEADER_SIZE + self.AUTH_TAG_SIZE:
            raise ValueError("数据包太短")

        msg_type = tunnel_packet[0]
        if msg_type != PacketType.DATA:
            raise ValueError(f"不是数据消息, 类型: {msg_type}")

        seq = struct.unpack("!Q", tunnel_packet[1:9])[0]
        nonce = tunnel_packet[9:21]
        ciphertext_with_tag = tunnel_packet[21:]

        if not self.rx_replay.check_and_update(seq):
            raise ValueError(f"重放攻击检测, 序列号: {seq}")

        ad = struct.pack("!BQ", msg_type, seq)

        try:
            plaintext = self.crypto.decrypt(ciphertext_with_tag, nonce, ad)
        except Exception as e:
            raise ValueError(f"认证失败, 数据可能被篡改: {e}")

        return plaintext

    def pack_heartbeat(self, is_ack: bool = False) -> bytes:
        """
        封装心跳包

        心跳包用于:
        1. 维持 NAT 映射 (防止 UDP 端口被回收)
        2. 检测隧道连通性
        3. 测量往返延迟

        心跳包也被加密和认证, 防止攻击者伪造心跳包扰乱隧道状态。
        """
        if not self.crypto:
            msg_type = PacketType.HEARTBEAT_ACK if is_ack else PacketType.HEARTBEAT
            seq = self.tx_replay.next_sequence() if is_ack else 0
            return struct.pack("!BQ", msg_type, seq) + b"\x00" * 12 + b"\x00" * 16

        seq = self.tx_replay.next_sequence()
        nonce = os.urandom(12)

        msg_type = PacketType.HEARTBEAT_ACK if is_ack else PacketType.HEARTBEAT
        header = struct.pack("!BQ", msg_type, seq) + nonce
        ad = struct.pack("!BQ", msg_type, seq)

        payload = struct.pack("!Q", seq)
        ciphertext_with_tag = self.crypto.encrypt(payload, nonce, ad)

        return header + ciphertext_with_tag

    def unpack_heartbeat(self, tunnel_packet: bytes) -> tuple:
        """
        解封装心跳包

        Returns:
            tuple: (is_ack, sequence_number)
        """
        if len(tunnel_packet) < self.HEADER_SIZE:
            raise ValueError("心跳包太短")

        msg_type = tunnel_packet[0]
        if msg_type not in (PacketType.HEARTBEAT, PacketType.HEARTBEAT_ACK):
            raise ValueError(f"不是心跳消息, 类型: {msg_type}")

        seq = struct.unpack("!Q", tunnel_packet[1:9])[0]
        is_ack = msg_type == PacketType.HEARTBEAT_ACK

        if self.crypto:
            if not self.rx_replay.check_and_update(seq):
                raise ValueError(f"重放攻击检测 (心跳), 序列号: {seq}")

            nonce = tunnel_packet[9:21]
            ciphertext_with_tag = tunnel_packet[21:]
            ad = struct.pack("!BQ", msg_type, seq)
            try:
                self.crypto.decrypt(ciphertext_with_tag, nonce, ad)
            except Exception as e:
                raise ValueError(f"心跳认证失败: {e}")

        return is_ack, seq

    @staticmethod
    def get_packet_type(tunnel_packet: bytes) -> int:
        """快速获取数据包类型 (无需解密)"""
        if not tunnel_packet:
            return -1
        return tunnel_packet[0]


def build_handshake_packet(handshake_type: int, payload: bytes) -> bytes:
    """
    构造握手消息包 (握手阶段还没有会话密钥, 所以明文传输)

    握手消息格式:
    +--------+----------------+
    |  类型  |    负载        |
    | 1字节  |    变长        |
    +--------+----------------+
    """
    return struct.pack("!B", handshake_type) + payload


def parse_handshake_packet(packet: bytes) -> tuple:
    """解析握手消息包"""
    if len(packet) < 1:
        raise ValueError("握手包太短")
    msg_type = packet[0]
    payload = packet[1:]
    return msg_type, payload
