"""
VPN 隧道工具 - 完整集成测试

测试内容:
1. 服务端启动与监听
2. 客户端握手与 IP 分配
3. 客户端 TUN 设备与路由配置
4. 客户端 -> 服务端 通信 [模拟 TUN]
5. 客户端 1 <-> 客户端 2 通信 [模拟 TUN]
6. 客户端 -> 服务端 通信 [真实 TUN] (Linux 可用时)
7. 客户端 1 <-> 客户端 2 通信 [真实 TUN] (Linux 可用时)
8. 客户端断开重连
9. IP 地址分配策略
10. 多客户端按地址转发

两种模式:
- 真实 TUN 模式: Linux + root, 通过 SO_BINDTODEVICE 绑定到客户端 TUN 接口发包
  包路径: ping(绑定到 tun_c1) -> 客户端1 TUN read -> 加密 -> UDP -> 服务端
- 模拟 TUN 模式: 所有系统通用, inject_rx_packet 注入
  两种模式都走完整 UDP socket 链路, 并使用 delivery_log / tx/rx 记录验收
"""

import sys
import os
import time
import struct
import socket
import threading
import platform
import traceback
import ctypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_server import VPNServer
from vpn_client import VPNClient, ClientDeliveryRecord
from tun_device import parse_ip_header

SO_BINDTODEVICE = 25  # Linux socket.h 常量


def is_real_tun_available() -> bool:
    """检测系统是否支持真实 TUN 设备 (Linux + /dev/net/tun 可打开 + 可能有 root)"""
    if platform.system() != "Linux":
        return False
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        os.close(fd)
        return True
    except (FileNotFoundError, PermissionError, OSError):
        return False


def build_icmp_ping(src_ip: str, dst_ip: str, seq: int = 1) -> bytes:
    """构造 ICMP Echo Request (不包含 IP 头, 用于 raw socket IPPROTO_ICMP)"""
    def checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    icmp_type = 8
    icmp_code = 0
    icmp_id = 0x1234
    icmp_seq = seq
    icmp_data = b"VPN-TEST-PAYLOAD-" + struct.pack("!IH", int(time.time()), seq)

    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
    icmp_checksum = checksum(icmp_header + icmp_data)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    return icmp_header + icmp_data


def build_full_ip_packet(src_ip: str, dst_ip: str, icmp_payload: bytes) -> bytes:
    """在 ICMP 外面包一层 IP 头 (用于模拟模式注入、以及关键字段比对基准)"""
    def checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_total_len = 20 + len(icmp_payload)
    ip_id = 0xABCD
    ip_flags = 0
    ip_ttl = 64
    ip_proto = 1
    ip_checksum = 0

    ip_header = struct.pack("!BBHHHBBH4s4s",
                            (ip_ver << 4) + ip_ihl,
                            ip_tos,
                            ip_total_len,
                            ip_id,
                            ip_flags,
                            ip_ttl,
                            ip_proto,
                            ip_checksum,
                            src,
                            dst)
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            (ip_ver << 4) + ip_ihl,
                            ip_tos,
                            ip_total_len,
                            ip_id,
                            ip_flags,
                            ip_ttl,
                            ip_proto,
                            ip_checksum,
                            src,
                            dst)
    return ip_header + icmp_payload


def send_icmp_via_bindtodevice(dst_ip: str, icmp_payload: bytes, bind_device: str) -> bool:
    """真实 TUN 模式下发包: raw socket + SO_BINDTODEVICE 绑定到客户端的 TUN 接口
    这样包会从指定的 TUN 接口出去, 被客户端的 _tun_read_loop 真正读到, 走完整系统入口路径
    """
    if platform.system() != "Linux":
        raise RuntimeError("SO_BINDTODEVICE 仅 Linux 可用")

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                        bind_device.encode('ascii') + b'\x00')
    except OSError as e:
        sock.close()
        raise PermissionError(f"SO_BINDTODEVICE 失败 (需要 root?): {e}")

    try:
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
        sock.sendto(icmp_payload, (dst_ip, 0))
        return True
    finally:
        sock.close()


class TestResult:
    """测试结果收集器"""

    def __init__(self):
        self.passed = []
        self.failed = []
        self.errors = []
        self.skipped = []

    def ok(self, name: str, detail: str = ""):
        self.passed.append((name, detail))
        print(f"  ✅ {name} {detail}")

    def fail(self, name: str, detail: str = ""):
        self.failed.append((name, detail))
        print(f"  ❌ {name} {detail}")

    def error(self, name: str, exception: Exception):
        self.errors.append((name, exception))
        print(f"  💥 {name} - 异常: {exception}")
        traceback.print_exc()

    def skip(self, name: str, reason: str = ""):
        self.skipped.append((name, reason))
        print(f"  ⏭️  跳过: {name} ({reason})")

    def summary(self):
        print("\n" + "=" * 60)
        print("测试结果汇总")
        print("=" * 60)
        print(f"通过: {len(self.passed)}  失败: {len(self.failed)}  跳过: {len(self.skipped)}  异常: {len(self.errors)}")
        print("-" * 60)
        if self.passed:
            print("\n✅ 通过的测试:")
            for name, detail in self.passed:
                print(f"   - {name} {detail}")
        if self.failed:
            print("\n❌ 失败的测试:")
            for name, detail in self.failed:
                print(f"   - {name} {detail}")
        if self.skipped:
            print("\n⏭️  跳过的测试:")
            for name, reason in self.skipped:
                print(f"   - {name} ({reason})")
        if self.errors:
            print("\n💥 异常的测试:")
            for name, exc in self.errors:
                print(f"   - {name}: {exc}")
        print("-" * 60)
        return len(self.failed) == 0 and len(self.errors) == 0


# ============================================================
# C-S 通信测试 (模拟 TUN 模式)
# ============================================================
def run_cs_test_simulate(result: TestResult, server: VPNServer, client1: VPNClient,
                         client1_ip: str):
    """C-S 通信 [模拟 TUN]: inject_rx_packet 注入, delivery_log + TUN 队列双验证"""
    mode = "模拟 TUN"
    print(f"\n【测试 5】客户端 1 -> 服务端 通信 (C-S) [{mode}]")
    print("-" * 60)

    icmp_payload = build_icmp_ping(client1_ip, server.tun_ip, seq=1)
    ping_packet = build_full_ip_packet(client1_ip, server.tun_ip, icmp_payload)
    src, dst, proto = parse_ip_header(ping_packet)
    print(f"  构造测试包: {src} -> {dst}, 协议={proto}")

    server.delivery_log.clear()
    client1.delivery_log.clear()
    server.tun.get_tx_packets(clear=True)

    print("  [步骤 1/4] 注入测试包到客户端 1 TUN")
    client1.tun.inject_rx_packet(ping_packet)

    # 步骤 1: 等待客户端1 tx (从 TUN 读到)
    print("  [步骤 2/4] 等待客户端 1 从 TUN 读到包...")
    c1_tx = client1.delivery_log.wait_for(
        lambda r: r["direction"] == "tx" and r["dst_ip"] == server.tun_ip,
        timeout=5.0,
    )
    if not c1_tx:
        result.fail(f"C-S [{mode}] 客户端1未发出", "5秒内无 tx 记录")
        return
    print(f"  ✅ 已发送 (客户端1 delivery_log tx: {c1_tx['src_ip']}->{c1_tx['dst_ip']})")

    # 步骤 2: 等待服务端 delivered_server
    print("  [步骤 3/4] 等待服务端到达...")
    srv_rec = server.delivery_log.wait_for(
        lambda r: r["dst_ip"] == server.tun_ip and r["action"] == "delivered_server",
        timeout=5.0,
    )
    if not srv_rec:
        result.fail(f"C-S [{mode}] 服务端未收到", f"无 delivered_server 记录 (dst={server.tun_ip})")
        all_recs = server.delivery_log.get_all()
        if all_recs:
            print(f"    服务端已有记录: {all_recs}")
        return
    print(f"  ✅ 已到达服务端 (delivery_log: {srv_rec['action']}, {srv_rec['detail']})")

    # 步骤 3: 比对关键字段 + TUN 队列
    srv_tx_pkts = server.tun.get_tx_packets(clear=False)
    ok_srv = srv_tx_pkts and srv_tx_pkts[-1] == ping_packet
    same, diffs = ClientDeliveryRecord.compare_key_fields(c1_tx, {
        "src_ip": client1_ip, "dst_ip": server.tun_ip, "protocol": 1,
        "icmp_payload": icmp_payload,
    })
    if same and ok_srv:
        print("  ✅ 关键字段一致 & 服务端 TUN 队列内容正确")
        result.ok(f"C-S 通信正常 [{mode}]", "完整链路: 注入→TUN读→加密→UDP→服务端解密→路由→TUN写")
    else:
        msg_parts = []
        if not same:
            msg_parts.append(f"关键字段差异: {diffs}")
        if not ok_srv:
            msg_parts.append(f"TUN队列为空或内容不一致 (包数={len(srv_tx_pkts)})")
        result.fail(f"C-S [{mode}] 内容不一致", "; ".join(msg_parts))


# ============================================================
# C-C 转发测试 (模拟 TUN 模式)
# ============================================================
def run_cc_test_simulate(result: TestResult, server: VPNServer, client1: VPNClient, client2: VPNClient,
                         client1_ip: str, client2_ip: str):
    """C-C 转发 [模拟 TUN]: inject_rx_packet 注入, tx/服务端forwarded/rx 三步断言"""
    mode = "模拟 TUN"
    print(f"\n【测试 6】客户端 1 -> 客户端 2 通信 (C-C 转发) [{mode}]")
    print("-" * 60)

    icmp_payload = build_icmp_ping(client1_ip, client2_ip, seq=2)
    ping_packet = build_full_ip_packet(client1_ip, client2_ip, icmp_payload)
    src, dst, proto = parse_ip_header(ping_packet)
    print(f"  构造测试包: {src} -> {dst}, 协议={proto}")

    next_hop = server.route_table.lookup(client2_ip)
    client2_peer_addr = server.transport.get_peer_by_tun_ip(client2_ip)
    if next_hop and client2_peer_addr:
        result.ok("服务端路由表正确", f"{client2_ip} -> {client2_peer_addr}")
    else:
        result.fail("服务端路由表缺失", f"找不到 {client2_ip} 的下一跳")
        return

    server.delivery_log.clear()
    client1.delivery_log.clear()
    client2.delivery_log.clear()
    client2.tun.get_tx_packets(clear=True)

    print("  [步骤 1/5] 注入测试包到客户端 1 TUN")
    client1.tun.inject_rx_packet(ping_packet)

    # 1. 客户端1 tx
    print("  [步骤 2/5] 等待客户端1发出...")
    c1_tx = client1.delivery_log.wait_for(
        lambda r: r["direction"] == "tx" and r["dst_ip"] == client2_ip,
        timeout=5.0,
    )
    if not c1_tx:
        result.fail(f"C-C [{mode}] 客户端1未发出", "5秒内无 tx 记录")
        return
    print(f"  ✅ 已发送 (客户端1 tx: {c1_tx['src_ip']}->{c1_tx['dst_ip']})")

    # 2. 服务端 forwarded
    print("  [步骤 3/5] 等待服务端转发...")
    fwd_rec = server.delivery_log.wait_for(
        lambda r: r["dst_ip"] == client2_ip and r["action"] == "forwarded",
        timeout=5.0,
    )
    if not fwd_rec:
        result.fail(f"C-C [{mode}] 服务端未转发", f"5秒内无 forwarded 记录 (dst={client2_ip})")
        return
    print(f"  ✅ 已转发 (服务端 delivery_log: {fwd_rec['action']}, {fwd_rec['detail']})")

    # 3. 客户端2 rx
    print("  [步骤 4/5] 等待客户端2到达...")
    c2_rx = client2.delivery_log.wait_for(
        lambda r: r["direction"] == "rx" and r["dst_ip"] == client2_ip,
        timeout=5.0,
    )
    if not c2_rx:
        result.fail(f"C-C [{mode}] 客户端2未收到", f"5秒内无 rx 记录 (dst={client2_ip})")
        return
    print(f"  ✅ 已到达对端 (客户端2 rx: {c2_rx['src_ip']}->{c2_rx['dst_ip']})")

    # 4. 比对关键字段 (实际经过隧道的 c1_tx 包 vs c2_rx 包)
    same, diffs = ClientDeliveryRecord.compare_key_fields(c1_tx, c2_rx)
    c2_tun_ok = bool(client2.tun.get_tx_packets(clear=False))
    if same and c2_tun_ok:
        print("  ✅ 客户端1发出与客户端2收到关键字段一致 (src_ip/dst_ip/protocol/ICMP payload)")
        result.ok(f"C-C 转发链路正常 [{mode}]",
                  f"完整链路: 注入→TUN读→加密→UDP→服务端转发(→{client2_ip})→UDP→解密→关键字段一致")
    else:
        parts = []
        if not same:
            parts.append(f"关键字段差异: {diffs}")
        if not c2_tun_ok:
            parts.append("客户端2 TUN队列为空")
        result.fail(f"C-C [{mode}] 内容不一致", "; ".join(parts))


# ============================================================
# C-S 通信测试 (真实 TUN 模式)
# ============================================================
def run_cs_test_real(result: TestResult, server: VPNServer, client1: VPNClient,
                     client1_ip: str, client1_tun_name: str):
    """C-S 通信 [真实 TUN]: raw socket + SO_BINDTODEVICE 绑定到客户端1 TUN 接口发包"""
    mode = "真实 TUN"
    print(f"\n【测试 7】客户端 1 -> 服务端 通信 (C-S) [{mode}]")
    print("-" * 60)

    icmp_payload = build_icmp_ping(client1_ip, server.tun_ip, seq=11)

    server.delivery_log.clear()
    client1.delivery_log.clear()

    try:
        print(f"  [步骤 1/4] SO_BINDTODEVICE={client1_tun_name} 发 ICMP -> {server.tun_ip}")
        send_icmp_via_bindtodevice(server.tun_ip, icmp_payload, client1_tun_name)
    except PermissionError as e:
        result.skip(f"C-S [{mode}]", f"无 root 权限或 SO_BINDTODEVICE 失败: {e}")
        return
    except RuntimeError as e:
        result.skip(f"C-S [{mode}]", str(e))
        return
    except Exception as e:
        result.fail(f"C-S [{mode}] 发包异常", str(e))
        return

    # 1. 客户端1 tx (从系统 TUN 接口真的读到, 不是注入)
    print("  [步骤 2/4] 等待客户端1从 TUN 读到...")
    c1_tx = client1.delivery_log.wait_for(
        lambda r: r["direction"] == "tx" and r["dst_ip"] == server.tun_ip,
        timeout=8.0,
    )
    if not c1_tx:
        result.fail(f"C-S [{mode}] 客户端1 TUN未读到包",
                     f"8秒内无 tx 记录 (绑定了 {client1_tun_name}, 包未走客户端 TUN?)")
        return
    print(f"  ✅ 已发送 (客户端1从 TUN 读到: {c1_tx['src_ip']}->{c1_tx['dst_ip']}, 从系统入口进来!)")

    # 2. 服务端 delivered_server
    print("  [步骤 3/4] 等待服务端到达...")
    srv_rec = server.delivery_log.wait_for(
        lambda r: r["dst_ip"] == server.tun_ip and r["action"] == "delivered_server",
        timeout=5.0,
    )
    if not srv_rec:
        result.fail(f"C-S [{mode}] 服务端未收到", f"无 delivered_server 记录 (dst={server.tun_ip})")
        all_recs = server.delivery_log.get_all()
        if all_recs:
            print(f"    服务端已有记录: {all_recs}")
        return
    print(f"  ✅ 已到达服务端 (delivery_log: {srv_rec['action']}, {srv_rec['detail']})")

    # 3. 比对关键字段 (实际经过系统入口+TUN的真实包, 不是手工构造的那份)
    same, diffs = ClientDeliveryRecord.compare_key_fields(c1_tx, {
        "src_ip": client1_ip, "dst_ip": server.tun_ip, "protocol": 1,
        "icmp_payload": icmp_payload,
    })
    if same:
        print("  ✅ 关键字段一致 (src_ip/dst_ip/protocol/ICMP payload)")
        result.ok(f"C-S 通信正常 [{mode}]",
                  f"完整链路: raw socket({client1_tun_name})→TUNread→加密→UDP→服务端解密→路由→到达")
    else:
        result.fail(f"C-S [{mode}] 关键字段不一致", f"差异: {diffs}")


# ============================================================
# C-C 转发测试 (真实 TUN 模式)
# ============================================================
def run_cc_test_real(result: TestResult, server: VPNServer, client1: VPNClient, client2: VPNClient,
                     client1_ip: str, client2_ip: str, client1_tun_name: str):
    """C-C 转发 [真实 TUN]: SO_BINDTODEVICE 从客户端1 TUN 发包, 按真实经过隧道的 tx/rx 比对"""
    mode = "真实 TUN"
    print(f"\n【测试 8】客户端 1 -> 客户端 2 通信 (C-C 转发) [{mode}]")
    print("-" * 60)

    icmp_payload = build_icmp_ping(client1_ip, client2_ip, seq=12)

    next_hop = server.route_table.lookup(client2_ip)
    client2_peer_addr = server.transport.get_peer_by_tun_ip(client2_ip)
    if next_hop and client2_peer_addr:
        result.ok("服务端路由表正确", f"{client2_ip} -> {client2_peer_addr}")
    else:
        result.fail("服务端路由表缺失", f"找不到 {client2_ip} 的下一跳")
        return

    server.delivery_log.clear()
    client1.delivery_log.clear()
    client2.delivery_log.clear()

    try:
        print(f"  [步骤 1/5] SO_BINDTODEVICE={client1_tun_name} 发 ICMP -> {client2_ip}")
        send_icmp_via_bindtodevice(client2_ip, icmp_payload, client1_tun_name)
    except PermissionError as e:
        result.skip(f"C-C [{mode}]", f"无 root 权限或 SO_BINDTODEVICE 失败: {e}")
        return
    except RuntimeError as e:
        result.skip(f"C-C [{mode}]", str(e))
        return
    except Exception as e:
        result.fail(f"C-C [{mode}] 发包异常", str(e))
        return

    # 1. 客户端1 tx (真实从 TUN 读到)
    print("  [步骤 2/5] 等待客户端1从 TUN 读到...")
    c1_tx = client1.delivery_log.wait_for(
        lambda r: r["direction"] == "tx" and r["dst_ip"] == client2_ip,
        timeout=8.0,
    )
    if not c1_tx:
        result.fail(f"C-C [{mode}] 客户端1 TUN未读到包",
                     f"8秒内无 tx 记录 (绑定 {client1_tun_name}, 包未走客户端 TUN?)")
        return
    print(f"  ✅ 已发送 (客户端1从 TUN 读到: {c1_tx['src_ip']}->{c1_tx['dst_ip']}, 从系统入口进来!)")

    # 2. 服务端 forwarded
    print("  [步骤 3/5] 等待服务端转发...")
    fwd_rec = server.delivery_log.wait_for(
        lambda r: r["dst_ip"] == client2_ip and r["action"] == "forwarded",
        timeout=5.0,
    )
    if not fwd_rec:
        result.fail(f"C-C [{mode}] 服务端未转发", f"无 forwarded 记录 (dst={client2_ip})")
        return
    print(f"  ✅ 已转发 (服务端 delivery_log: {fwd_rec['action']}, {fwd_rec['detail']})")

    # 3. 客户端2 rx (真实到达)
    print("  [步骤 4/5] 等待客户端2到达...")
    c2_rx = client2.delivery_log.wait_for(
        lambda r: r["direction"] == "rx" and r["dst_ip"] == client2_ip,
        timeout=5.0,
    )
    if not c2_rx:
        result.fail(f"C-C [{mode}] 客户端2未收到", f"5秒内无 rx 记录 (dst={client2_ip})")
        return
    print(f"  ✅ 已到达对端 (客户端2 rx: {c2_rx['src_ip']}->{c2_rx['dst_ip']})")

    # 4. 关键字段比对: 客户端1实际发出 (经过系统入口+TUN) vs 客户端2实际到达
    same, diffs = ClientDeliveryRecord.compare_key_fields(c1_tx, c2_rx)
    if same:
        print("  ✅ 客户端1真实发出 与 客户端2实际到达 关键字段一致 (src/dst/proto/ICMP payload)")
        result.ok(f"C-C 转发链路正常 [{mode}]",
                  f"完整链路: raw sock({client1_tun_name})→TUNread→加密→UDP→服务端转发→UDP→解密→关键字段一致")
    else:
        result.fail(f"C-C [{mode}] 关键字段不一致", f"差异: {diffs}")


# ============================================================
# 主流程
# ============================================================
def run_integration_test():
    result = TestResult()

    real_tun = is_real_tun_available()

    print("\n" + "=" * 60)
    print("VPN 隧道集成测试")
    print("=" * 60)
    print(f"  系统: {platform.system()}")
    print(f"  真实 TUN 能力: {'可用' if real_tun else '不可用 (将跳过真实 TUN 用例)'}")
    if not real_tun:
        if platform.system() != "Linux":
            print(f"  原因: 非 Linux 系统")
        else:
            print(f"  原因: /dev/net/tun 不可打开 (无权限或设备不存在)")
    print()

    # 设备名隔离 (100+ 避免与系统 tun0/tun1 冲突)
    SERVER_TUN = "tun100"
    CLIENT1_TUN = "tun101"
    CLIENT2_TUN = "tun102"

    server = None
    client1 = None
    client2 = None

    try:
        # ----------------- 测试 1: 启动服务端 -----------------
        print(f"【测试 1】启动服务端")
        print("-" * 60)

        server = VPNServer(
            listen_host="127.0.0.1",
            listen_port=0,
            tun_ip="10.0.0.1",
            tun_netmask="255.255.255.0",
            tun_name=SERVER_TUN,
            client_network="10.0.0.0",
            client_netmask="255.255.255.0",
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        server.start()

        server_port = server.transport.sock.getsockname()[1]
        print(f"  服务端监听端口: {server_port}")
        print(f"  服务端 TUN 设备: {SERVER_TUN}, 虚拟 IP: {server.tun_ip}")

        if server.tun and server.tun.get_config()["is_up"]:
            result.ok("服务端 TUN 设备启动", f"设备={SERVER_TUN}, IP={server.tun_ip}")
        else:
            result.fail("服务端 TUN 设备启动失败")

        if server.tun_ip in server.ip_allocator.exclude_ips:
            result.ok("服务端 IP 已排除在地址池外")
        else:
            result.fail("服务端 IP 未排除")

        time.sleep(0.5)

        # ----------------- 测试 2: 客户端 1 握手 -----------------
        print(f"\n【测试 2】客户端 1 握手与 IP 分配")
        print("-" * 60)

        client1 = VPNClient(
            server_host="127.0.0.1",
            server_port=server_port,
            routes=[("10.0.0.0", "255.255.255.0")],
            tun_name=CLIENT1_TUN,
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        client1.start()

        connect_ok = client1.wait_for_connection(timeout=10)
        if not connect_ok:
            result.fail("客户端 1 握手超时", f"阶段={client1._handshake_stage}")
            raise RuntimeError("客户端 1 连接失败, 后续测试无法继续")

        result.ok("客户端 1 握手完成", f"阶段={client1._handshake_stage}")

        client1_ip = client1.tun_ip
        if client1_ip:
            result.ok("客户端 1 获得虚拟 IP", f"IP={client1_ip}")
        else:
            result.fail("客户端 1 未获得 IP")

        if client1_ip != server.tun_ip:
            result.ok("客户端 IP 不与服务端冲突", f"客户端={client1_ip}, 服务端={server.tun_ip}")
        else:
            result.fail("客户端 IP 与服务端冲突")

        if client1_ip == "10.0.0.2":
            result.ok("客户端 IP 从 10.0.0.2 开始分配")
        else:
            result.ok("客户端 IP 已分配", f"IP={client1_ip}")

        server_client1 = server.wait_for_client(timeout=5)
        if server_client1 and server_client1["tun_ip"] == client1_ip:
            result.ok("服务端看到客户端 1 已连接", f"IP={client1_ip}")
        else:
            result.fail("服务端未看到客户端 1")

        # ----------------- 测试 3: TUN + 路由 -----------------
        print(f"\n【测试 3】客户端 1 TUN 设备与路由配置")
        print("-" * 60)

        tun_config = client1.tun.get_config()
        if tun_config["ip"] == client1_ip:
            result.ok("TUN 设备 IP 配置正确", f"设备={CLIENT1_TUN}, IP={tun_config['ip']}/{tun_config['prefix_len']}")
        else:
            result.fail("TUN 设备 IP 配置错误")

        if tun_config["is_up"]:
            result.ok("TUN 设备已启用")
        else:
            result.fail("TUN 设备未启用")

        routes = client1.route_manager.added_routes if client1.route_manager else []
        if ("10.0.0.0", "255.255.255.0") in routes:
            result.ok("路由配置正确", f"路由表: {routes}")
        else:
            result.fail("路由配置缺失")

        # ----------------- 测试 4: 客户端 2 -----------------
        print(f"\n【测试 4】客户端 2 连接与 IP 分配")
        print("-" * 60)

        client2 = VPNClient(
            server_host="127.0.0.1",
            server_port=server_port,
            routes=[("10.0.0.0", "255.255.255.0")],
            tun_name=CLIENT2_TUN,
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        client2.start()

        connect_ok = client2.wait_for_connection(timeout=10)
        if not connect_ok:
            result.fail("客户端 2 握手超时", f"阶段={client2._handshake_stage}")
        else:
            result.ok("客户端 2 握手完成")

        client2_ip = client2.tun_ip
        if client2_ip:
            result.ok("客户端 2 获得虚拟 IP", f"IP={client2_ip}")
        else:
            result.fail("客户端 2 未获得 IP")

        if client1_ip and client2_ip and client1_ip != client2_ip:
            result.ok("两个客户端 IP 不同", f"客户端1={client1_ip}, 客户端2={client2_ip}")
        else:
            result.fail("客户端 IP 冲突")

        connected_clients = server.get_connected_clients()
        if len(connected_clients) == 2:
            result.ok("服务端看到两个客户端在线", f"共 {len(connected_clients)} 个")
        else:
            result.fail("服务端客户端数量不对")

        # ----------------- 测试 5: C-S [模拟 TUN] -----------------
        run_cs_test_simulate(result, server, client1, client1_ip)

        # ----------------- 测试 6: C-C [模拟 TUN] -----------------
        run_cc_test_simulate(result, server, client1, client2, client1_ip, client2_ip)

        # ----------------- 测试 7 & 8: 真实 TUN -----------------
        if real_tun:
            run_cs_test_real(result, server, client1, client1_ip, CLIENT1_TUN)
            run_cc_test_real(result, server, client1, client2, client1_ip, client2_ip, CLIENT1_TUN)
        else:
            result.skip("C-S 通信 [真实 TUN]",
                        f"真实 TUN 不可用 (系统={platform.system()}, /dev/net/tun不可打开)")
            result.skip("C-C 转发 [真实 TUN]",
                        f"真实 TUN 不可用 (系统={platform.system()}, /dev/net/tun不可打开)")

        # ----------------- 测试 9: 断开重连 -----------------
        print(f"\n【测试 9】客户端 1 断开重连")
        print("-" * 60)

        old_ip = client1_ip
        client1_peer_addr = server.transport.get_peer_by_tun_ip(client1_ip)
        client1.stop()
        print(f"  客户端 1 已停止, 原 IP={old_ip}")
        time.sleep(0.5)

        if client1_peer_addr:
            server.disconnect_peer(client1_peer_addr)
        time.sleep(0.2)

        server_clients_after = server.get_connected_clients()
        client1_still_there = any(c["tun_ip"] == old_ip for c in server_clients_after)
        if not client1_still_there:
            result.ok("服务端已清理断开的客户端")
        else:
            result.fail("服务端未清理断开的客户端")

        if not server.ip_allocator.is_allocated(old_ip):
            result.ok("IP 已释放回地址池", f"IP={old_ip}")
        else:
            result.fail("IP 未释放")

        print("  重新启动客户端 1...")
        client1 = VPNClient(
            server_host="127.0.0.1",
            server_port=server_port,
            routes=[("10.0.0.0", "255.255.255.0")],
            tun_name=CLIENT1_TUN,
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        client1.start()

        connect_ok = client1.wait_for_connection(timeout=10)
        if connect_ok:
            result.ok("客户端 1 重连成功", f"新 IP={client1.tun_ip}")
            client1_ip = client1.tun_ip
        else:
            result.fail("客户端 1 重连超时", f"阶段={client1._handshake_stage}")

        if client1.tun and client1.tun.get_config()["is_up"]:
            result.ok("重连后 TUN 设备已重新配置", f"IP={client1.tun_ip}")
        else:
            result.fail("重连后 TUN 设备配置失败")

        if client1.route_manager and client1.route_manager.added_routes:
            result.ok("重连后路由已重新配置")
        else:
            result.fail("重连后路由配置失败")

        # ----------------- 测试 10: IP 分配策略 -----------------
        print(f"\n【测试 10】IP 地址分配策略")
        print("-" * 60)

        all_clients = server.get_connected_clients()
        all_ips = [c["tun_ip"] for c in all_clients if c["tun_ip"]]

        if server.tun_ip not in all_ips:
            result.ok("服务端 IP 未分配给客户端")
        else:
            result.fail("服务端 IP 被分配给客户端")

        if len(all_ips) == len(set(all_ips)):
            result.ok("所有客户端 IP 不重复")
        else:
            result.fail("存在重复 IP")

        # ----------------- 测试 11: 多客户端按地址转发 -----------------
        print(f"\n【测试 11】多客户端按虚拟 IP 转发验证")
        print("-" * 60)

        all_ips = []
        for c in server.get_connected_clients():
            ip = c["tun_ip"]
            peer = server.transport.get_peer_by_tun_ip(ip)
            if peer:
                result.ok(f"IP {ip} 映射正确", f"-> {peer}")
                all_ips.append(ip)
            else:
                result.fail(f"IP {ip} 找不到映射")

        if len(all_ips) >= 2:
            ip_a, ip_b = all_ips[0], all_ips[1]
            next_hop_a = server.route_table.lookup(ip_a)
            next_hop_b = server.route_table.lookup(ip_b)
            if next_hop_a and next_hop_b and next_hop_a != next_hop_b:
                result.ok("不同 IP 路由到不同对端")
            else:
                result.fail("路由查找失败或冲突")

    except Exception as e:
        result.error("集成测试异常", e)

    finally:
        print("\n" + "-" * 60)
        print("正在清理资源 (TUN 设备 & 路由)...")
        try:
            if client1:
                client1.stop()
        except Exception:
            pass
        try:
            if client2:
                client2.stop()
        except Exception:
            pass
        try:
            if server:
                server.stop()
        except Exception:
            pass
        print(f"资源清理完成 (设备: {SERVER_TUN}, {CLIENT1_TUN}, {CLIENT2_TUN})")

    success = result.summary()
    return success


if __name__ == "__main__":
    success = run_integration_test()
    sys.exit(0 if success else 1)
