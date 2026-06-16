"""
VPN 隧道工具功能测试
测试加密握手、数据包封装、路由等核心功能
"""

import sys
import os
import struct

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_handshake import Handshake, CryptoSession, ReplayProtector
from packet_encap import TunnelPacket, PacketType
from router import RouteTable, IPAllocator, ip_in_network


def test_crypto_session():
    """测试加密会话"""
    print("=" * 50)
    print("测试 1: 加密会话 (AES-GCM)")

    key = b"\x00" * 32
    session = CryptoSession(key)
    nonce = b"\x01" * 12
    plaintext = b"Hello, VPN World!"

    ciphertext = session.encrypt(plaintext, nonce)
    print(f"  明文: {plaintext}")
    print(f"  密文长度: {len(ciphertext)} 字节 (含 16 字节认证标签)")

    decrypted = session.decrypt(ciphertext, nonce)
    print(f"  解密结果: {decrypted}")
    assert decrypted == plaintext, "解密失败"

    try:
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        session.decrypt(tampered, nonce)
        assert False, "篡改检测失败"
    except Exception:
        print("  篡改检测: 通过 ✓")

    print("  加密会话测试: 通过 ✓")


def test_handshake():
    """测试握手协议"""
    print("=" * 50)
    print("测试 2: 握手协议 (X25519 ECDH)")

    client = Handshake(psk=b"test-psk")
    server = Handshake(psk=b"test-psk")

    client_hello = client.create_client_hello()
    print(f"  ClientHello 长度: {len(client_hello)} 字节 (1字节类型 + 32字节公钥)")

    server_hello = server.process_client_hello(client_hello)
    server.derive_session_key()
    print(f"  ServerHello 长度: {len(server_hello)} 字节")
    print(f"  服务端共享密钥长度: {len(server.shared_secret)} 字节")

    client.process_server_hello(server_hello)
    print(f"  客户端共享密钥长度: {len(client.shared_secret)} 字节")

    assert client.shared_secret == server.shared_secret, "共享密钥不一致"
    print("  共享密钥一致: 通过 ✓")

    server_finished = server.create_finished()
    assert client.verify_finished(server_finished), "服务端 Finished 验证失败"
    print("  服务端 Finished 验证: 通过 ✓")

    client_finished = client.create_finished()
    assert server.verify_finished(client_finished), "客户端 Finished 验证失败"
    print("  客户端 Finished 验证: 通过 ✓")

    print("  握手测试: 通过 ✓")
    return client, server


def test_packet_encap(client_handshake, server_handshake):
    """测试数据包封装"""
    print("=" * 50)
    print("测试 3: 数据包封装/解封装")

    client_pkt = TunnelPacket(client_handshake.session)
    server_pkt = TunnelPacket(server_handshake.session)

    ip_packet = b"\x45\x00\x00\x3c\x00\x01\x00\x00\x40\x06\x00\x00" + \
                 b"\x0a\x00\x00\x02" + b"\x0a\x00\x00\x01" + b"\x00" * 20
    print(f"  原始 IP 包长度: {len(ip_packet)} 字节")

    tunnel_pkt = client_pkt.pack_data(ip_packet)
    print(f"  隧道包长度: {len(tunnel_pkt)} 字节 (头部 21 + 密文 + 标签 16)")

    decrypted = server_pkt.unpack_data(tunnel_pkt)
    assert decrypted == ip_packet, "解封装失败"
    print("  解封装还原: 通过 ✓")

    try:
        tampered = bytearray(tunnel_pkt)
        tampered[25] ^= 0xFF
        server_pkt.unpack_data(bytes(tampered))
        assert False, "篡改检测失败"
    except ValueError as e:
        print(f"  篡改检测: 通过 ✓ ({e})")

    print("  数据包封装测试: 通过 ✓")


def test_replay_protection():
    """测试重放保护"""
    print("=" * 50)
    print("测试 4: 重放保护 (滑动窗口)")

    protector = ReplayProtector()

    seq1 = protector.next_sequence()
    seq2 = protector.next_sequence()
    seq3 = protector.next_sequence()
    print(f"  生成序列号: {seq1}, {seq2}, {seq3}")

    assert protector.check_and_update(seq1) == True, "新包应该接受"
    assert protector.check_and_update(seq2) == True, "新包应该接受"
    assert protector.check_and_update(seq3) == True, "新包应该接受"
    print("  正常新包: 通过 ✓")

    assert protector.check_and_update(seq1) == False, "重放包应该拒绝"
    assert protector.check_and_update(seq2) == False, "重放包应该拒绝"
    print("  重放包检测: 通过 ✓")

    seq100 = 100
    assert protector.check_and_update(seq100) == True, "大序列号应该接受并滑动窗口"
    print("  窗口滑动: 通过 ✓")

    assert protector.check_and_update(seq3) == False, "窗口外旧包应该拒绝"
    print("  窗口外旧包: 通过 ✓")

    print("  重放保护测试: 通过 ✓")


def test_heartbeat():
    """测试心跳包"""
    print("=" * 50)
    print("测试 5: 心跳包")

    key = b"\x01" * 32
    session = CryptoSession(key)
    pkt = TunnelPacket(session)

    heartbeat = pkt.pack_heartbeat(is_ack=False)
    print(f"  心跳请求长度: {len(heartbeat)} 字节")

    is_ack, seq = pkt.unpack_heartbeat(heartbeat)
    assert not is_ack, "应该是请求"
    print(f"  心跳序列号: {seq}")

    ack = pkt.pack_heartbeat(is_ack=True)
    is_ack2, seq2 = pkt.unpack_heartbeat(ack)
    assert is_ack2, "应该是应答"
    print("  心跳应答: 通过 ✓")

    print("  心跳测试: 通过 ✓")


def test_route_table():
    """测试路由表"""
    print("=" * 50)
    print("测试 6: 路由表")

    table = RouteTable()
    table.add_route("10.0.0.0", "255.255.255.0", ("1.1.1.1", 5000))
    table.add_route("10.0.1.0", "255.255.255.0", ("2.2.2.2", 5000))
    table.add_host_route("10.0.0.100", ("3.3.3.3", 5000))

    result = table.lookup("10.0.0.5")
    assert result == ("1.1.1.1", 5000), f"路由查找失败: {result}"
    print("  网段路由查找: 通过 ✓")

    result = table.lookup("10.0.0.100")
    assert result == ("3.3.3.3", 5000), "主机路由优先级不够"
    print("  主机路由优先: 通过 ✓")

    result = table.lookup("10.0.1.5")
    assert result == ("2.2.2.2", 5000), "第二条路由失败"
    print("  多路由区分: 通过 ✓")

    result = table.lookup("192.168.1.1")
    assert result is None, "未知网段应该返回 None"
    print("  未知网段: 通过 ✓")

    print("  路由表测试: 通过 ✓")


def test_ip_allocator():
    """测试 IP 分配器"""
    print("=" * 50)
    print("测试 7: IP 地址分配")

    allocator = IPAllocator("10.0.0.0", "255.255.255.0")

    ip1 = allocator.allocate("client1")
    ip2 = allocator.allocate("client2")
    print(f"  分配 IP1: {ip1}")
    print(f"  分配 IP2: {ip2}")

    assert ip1 != ip2, "IP 不应该重复"
    assert allocator.is_allocated(ip1), "IP 应该标记为已分配"
    print("  IP 不重复: 通过 ✓")

    ip1_again = allocator.allocate("client1")
    assert ip1_again == ip1, "同一客户端应该分配相同 IP"
    print("  同客户端复用: 通过 ✓")

    allocator.release("client1")
    assert not allocator.is_allocated(ip1), "释放后应该未分配"
    print("  IP 释放: 通过 ✓")

    ip3 = allocator.allocate("client3")
    assert ip3 == ip1, "释放的 IP 应该可以重新分配"
    print("  IP 回收复用: 通过 ✓")

    print("  IP 分配测试: 通过 ✓")


def test_ip_in_network():
    """测试网段判断"""
    print("=" * 50)
    print("测试 8: 网段包含判断")

    assert ip_in_network("192.168.1.5", "192.168.1.0", "255.255.255.0")
    assert not ip_in_network("192.168.2.5", "192.168.1.0", "255.255.255.0")
    assert ip_in_network("10.0.0.1", "10.0.0.0", "255.255.0.0")
    print("  网段判断: 通过 ✓")


def main():
    print("VPN 隧道工具功能测试")
    print("=" * 50)

    try:
        test_crypto_session()
        client_hs, server_hs = test_handshake()
        test_packet_encap(client_hs, server_hs)
        test_replay_protection()
        test_heartbeat()
        test_route_table()
        test_ip_allocator()
        test_ip_in_network()

        print("=" * 50)
        print("所有测试通过! ✓")
        print("=" * 50)
        return 0
    except AssertionError as e:
        print(f"\n测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n测试异常: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
