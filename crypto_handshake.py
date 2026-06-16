import os
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class CryptoSession:
    """
    加密会话 - 管理对称加密密钥和加解密操作

    使用 AES-256-GCM 认证加密算法, 同时提供:
    - 机密性 (Confidentiality): 数据包内容加密
    - 完整性 (Integrity): 检测数据包是否被篡改
    - 真实性 (Authenticity): 验证数据包来源

    AES-GCM 是 AEAD (Authenticated Encryption with Associated Data) 算法,
    支持附加数据 (AD) - 这些数据不加密但参与认证, 可用于保护协议头部。
    """

    def __init__(self, key: bytes):
        """
        初始化加密会话

        Args:
            key: 256位 (32字节) 对称密钥
        """
        if len(key) != 32:
            raise ValueError("密钥必须是 32 字节 (256 位)")
        self.key = key
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, nonce: bytes, associated_data: bytes = b"") -> bytes:
        """
        加密数据

        Args:
            plaintext: 明文数据
            nonce: 12字节随机数 (必须唯一, 无需保密)
            associated_data: 附加认证数据 (不加密, 但参与认证)

        Returns:
            bytes: ciphertext + tag (密文 + 16字节认证标签)
        """
        if len(nonce) != 12:
            raise ValueError("Nonce 必须是 12 字节")
        return self.aesgcm.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext_with_tag: bytes, nonce: bytes, associated_data: bytes = b"") -> bytes:
        """
        解密数据

        Args:
            ciphertext_with_tag: 密文 + 认证标签
            nonce: 12字节随机数 (与加密时相同)
            associated_data: 附加认证数据

        Returns:
            bytes: 明文数据

        Raises:
            Exception: 认证失败 (数据被篡改或密钥错误)
        """
        if len(nonce) != 12:
            raise ValueError("Nonce 必须是 12 字节")
        return self.aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)


class Handshake:
    """
    握手协议 - 基于 X25519 (ECDH) 的密钥协商

    握手流程:
    1. 客户端生成临时密钥对 (ephemeral key), 将公钥发送给服务端
    2. 服务端生成临时密钥对, 将公钥发送给客户端
    3. 双方使用自己的私钥和对方的公钥计算共享密钥 (ECDH)
    4. 双方使用 HKDF 从共享密钥派生会话密钥
    5. (可选) 使用预共享密钥 (PSK) 进行身份认证

    安全特性:
    - 前向保密 (Forward Secrecy): 每次会话使用新的临时密钥, 即使长期密钥泄露,
      过去的会话数据也不会被解密
    - 身份认证: 通过预共享密钥或签名验证对端身份
    """

    HANDSHAKE_MSG_CLIENT_HELLO = 1
    HANDSHAKE_MSG_SERVER_HELLO = 2
    HANDSHAKE_MSG_FINISHED = 3

    def __init__(self, psk: bytes = None):
        """
        初始化握手

        Args:
            psk: 预共享密钥 (Pre-Shared Key), 用于身份认证
        """
        self.psk = psk or b"vpn-demo-default-psk-2024"
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.session = None
        self.handshake_done = False

    def generate_keypair(self):
        """生成 X25519 临时密钥对"""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def compute_shared_secret(self, peer_public_key_bytes: bytes):
        """
        使用对端公钥计算共享密钥

        ECDH 原理:
        - 己方私钥 (a) * 对端公钥 (B) = 共享密钥
        - 对端私钥 (b) * 己方公钥 (A) = 共享密钥
        - 两者结果相同: a*B = a*b*G = b*A
        """
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        self.shared_secret = self.private_key.exchange(peer_public_key)
        return self.shared_secret

    def derive_session_key(self, salt: bytes = b"") -> CryptoSession:
        """
        使用 HKDF 从共享密钥派生会话密钥

        HKDF (HMAC-based Key Derivation Function):
        - 从一个共享秘密派生多个安全的密钥
        - 包括提取 (Extract) 和扩展 (Expand) 两步
        - 加入 context 信息确保不同用途的密钥不同
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt or self.psk,
            info=b"vpn-tunnel-session-key",
            backend=default_backend(),
        )
        session_key = hkdf.derive(self.shared_secret)
        self.session = CryptoSession(session_key)
        self.handshake_done = True
        return self.session

    def create_client_hello(self) -> bytes:
        """创建 ClientHello 消息"""
        pubkey_bytes = self.generate_keypair()
        msg_type = struct.pack("!B", self.HANDSHAKE_MSG_CLIENT_HELLO)
        return msg_type + pubkey_bytes

    def process_client_hello(self, data: bytes) -> bytes:
        """
        处理 ClientHello, 返回 ServerHello

        Returns:
            bytes: ServerHello 消息
        """
        msg_type = data[0]
        if msg_type != self.HANDSHAKE_MSG_CLIENT_HELLO:
            raise ValueError("不是 ClientHello 消息")

        client_pubkey = data[1:33]
        self.generate_keypair()
        self.compute_shared_secret(client_pubkey)

        server_pubkey = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        msg_type = struct.pack("!B", self.HANDSHAKE_MSG_SERVER_HELLO)
        return msg_type + server_pubkey

    def process_server_hello(self, data: bytes):
        """处理 ServerHello, 完成密钥协商"""
        msg_type = data[0]
        if msg_type != self.HANDSHAKE_MSG_SERVER_HELLO:
            raise ValueError("不是 ServerHello 消息")

        server_pubkey = data[1:33]
        self.compute_shared_secret(server_pubkey)
        self.derive_session_key()

    def verify_finished(self, data: bytes) -> bool:
        """
        验证 Finished 消息 (使用 HMAC 验证对端是否持有正确的密钥)

        原理:
        - 双方都计算握手消息的 HMAC
        - 如果对方能生成正确的 HMAC, 说明它拥有相同的会话密钥
        - 从而间接证明了身份 (因为只有知道 PSK 的才能派生出正确的密钥)
        """
        msg_type = data[0]
        if msg_type != self.HANDSHAKE_MSG_FINISHED:
            return False

        received_mac = data[1:]
        expected_mac = self._compute_finished_mac()
        return hmac.compare_digest(received_mac, expected_mac)

    def create_finished(self) -> bytes:
        """创建 Finished 消息"""
        msg_type = struct.pack("!B", self.HANDSHAKE_MSG_FINISHED)
        mac = self._compute_finished_mac()
        return msg_type + mac

    def _compute_finished_mac(self) -> bytes:
        """计算 Finished 消息的 HMAC"""
        h = hmac.new(self.session.key, self.shared_secret, hashlib.sha256)
        return h.digest()


class ReplayProtector:
    """
    重放保护 - 基于滑动窗口的序列号机制

    工作原理:
    1. 每个加密数据包都带有一个单调递增的序列号
    2. 接收方维护一个滑动窗口, 记录已经收到的序列号
    3. 如果收到的序列号:
       - 小于窗口左边界: 丢弃 (太旧, 可能是重放)
       - 在窗口内但已收到过: 丢弃 (重复, 重放攻击)
       - 在窗口内但未收到过: 接受, 标记为已收到
       - 大于窗口右边界: 接受, 滑动窗口

    配合 AEAD 认证标签, 可以同时防御:
    - 重放攻击 (Replay Attack): 攻击者截获数据包后重新发送
    - 篡改攻击 (Tampering): 攻击者修改数据包内容
    """

    WINDOW_SIZE = 64

    def __init__(self):
        self.next_seq = 0
        self.window_bitmap = 0
        self.max_seq = 0

    def next_sequence(self) -> int:
        """获取下一个发送序列号"""
        seq = self.next_seq
        self.next_seq += 1
        return seq

    def check_and_update(self, seq: int) -> bool:
        """
        检查序列号是否有效, 并更新窗口

        Args:
            seq: 收到的数据包序列号

        Returns:
            bool: True 表示有效, False 表示可能是重放包
        """
        if seq > self.max_seq:
            shift = seq - self.max_seq
            self.window_bitmap <<= shift
            self.window_bitmap |= 1
            self.max_seq = seq
            return True

        diff = self.max_seq - seq
        if diff >= self.WINDOW_SIZE:
            return False

        bit = 1 << diff
        if self.window_bitmap & bit:
            return False

        self.window_bitmap |= bit
        return True
