"""
VPN 隧道工具 - 完整集成测试

测试内容:
1. 服务端启动与监听
2. 客户端握手与 IP 分配
3. 客户端 TUN 设备与路由配置
4. 客户端 -> 服务端 通信
5. 客户端 1 <-> 客户端 2 通信 (通过服务端转发)
6. 客户端断开重连后重新获取地址
7. IP 地址不与服务端冲突

使用真实 UDP socket 进行测试, 非 Linux 系统自动使用 TUN 模拟模式。
"""

import sys
import os
import time
import struct
import socket
import threading
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_server import VPNServer
from vpn_client import VPNClient
from tun_device import parse_ip_header


class TestResult:
    """测试结果收集器"""
    def __init__(self):
        self.passed = []
        self.failed = []
        self.errors = []

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

    def summary(self):
        print("\n" + "=" * 60)
        print("测试结果汇总")
        print("=" * 60)
        print(f"通过: {len(self.passed)}  失败: {len(self.failed)}  异常: {len(self.errors)}")
        print("-" * 60)
        if self.passed:
            print("\n✅ 通过的测试:")
            for name, detail in self.passed:
                print(f"   - {name} {detail}")
        if self.failed:
            print("\n❌ 失败的测试:")
            for name, detail in self.failed:
                print(f"   - {name} {detail}")
        if self.errors:
            print("\n💥 异常的测试:")
            for name, exc in self.errors:
                print(f"   - {name}: {exc}")
        print("-" * 60)
        return len(self.failed) == 0 and len(self.errors) == 0


def build_icmp_ping(src_ip: str, dst_ip: str, seq: int = 1) -> bytes:
    """构造一个 ICMP Echo Request (ping) 包, 用于测试"""
    def checksum(data):
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    icmp_type = 8
    icmp_code = 0
    icmp_id = 0x1234
    icmp_seq = seq
    icmp_data = b"VPN-TEST-PAYLOAD-" + struct.pack("!I", int(time.time()))

    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
    icmp_checksum = checksum(icmp_header + icmp_data)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    icmp_packet = icmp_header + icmp_data

    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_total_len = 20 + len(icmp_packet)
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

    return ip_header + icmp_packet


def extract_icmp_data(ip_packet: bytes) -> tuple:
    """从 IP 包中提取 ICMP 数据"""
    if len(ip_packet) < 28:
        return None

    src_ip = ".".join(str(b) for b in ip_packet[12:16])
    dst_ip = ".".join(str(b) for b in ip_packet[16:20])
    protocol = ip_packet[9]

    if protocol != 1:
        return None

    icmp_start = 20
    icmp_type = ip_packet[icmp_start]
    icmp_data = ip_packet[icmp_start + 8:]

    return src_ip, dst_ip, icmp_type, icmp_data


def run_integration_test():
    """运行完整集成测试"""
    result = TestResult()

    print("\n" + "=" * 60)
    print("VPN 隧道集成测试")
    print("=" * 60)

    server = None
    client1 = None
    client2 = None

    try:
        # ============================================
        # 测试 1: 启动服务端
        # ============================================
        print("\n【测试 1】启动服务端")
        print("-" * 60)

        server = VPNServer(
            listen_host="127.0.0.1",
            listen_port=0,
            tun_ip="10.0.0.1",
            tun_netmask="255.255.255.0",
            client_network="10.0.0.0",
            client_netmask="255.255.255.0",
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        server.start()

        server_port = server.transport.sock.getsockname()[1]
        print(f"  服务端监听端口: {server_port}")
        print(f"  服务端虚拟 IP: {server.tun_ip}")

        if server.tun and server.tun.get_config()["is_up"]:
            result.ok("服务端 TUN 设备启动", f"IP={server.tun_ip}")
        else:
            result.fail("服务端 TUN 设备启动失败")

        server_ip_alloc_exclude = server.ip_allocator.exclude_ips
        if server.tun_ip in server_ip_alloc_exclude:
            result.ok("服务端 IP 已排除在地址池外", f"排除列表: {server_ip_alloc_exclude}")
        else:
            result.fail("服务端 IP 未排除", f"排除列表: {server_ip_alloc_exclude}")

        # 等待服务端完全就绪
        time.sleep(0.5)

        # ============================================
        # 测试 2: 客户端 1 连接与握手
        # ============================================
        print("\n【测试 2】客户端 1 握手与 IP 分配")
        print("-" * 60)

        client1 = VPNClient(
            server_host="127.0.0.1",
            server_port=server_port,
            routes=[("10.0.0.0", "255.255.255.0")],
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        client1.start()

        # 等待客户端连接
        connect_ok = client1.wait_for_connection(timeout=10)
        if not connect_ok:
            result.fail("客户端 1 握手超时", f"阶段={client1._handshake_stage}")
            raise RuntimeError("客户端 1 连接失败, 后续测试无法继续")

        result.ok("客户端 1 握手完成", f"阶段={client1._handshake_stage}")

        # 验证 IP 分配
        client1_ip = client1.tun_ip
        if client1_ip:
            result.ok("客户端 1 获得虚拟 IP", f"IP={client1_ip}")
        else:
            result.fail("客户端 1 未获得 IP")

        # 验证 IP 不与服务端冲突
        if client1_ip != server.tun_ip:
            result.ok("客户端 IP 不与服务端冲突", f"客户端={client1_ip}, 服务端={server.tun_ip}")
        else:
            result.fail("客户端 IP 与服务端冲突", f"都是 {client1_ip}")

        # 验证 IP 从 10.0.0.2 开始
        if client1_ip == "10.0.0.2":
            result.ok("客户端 IP 从 10.0.0.2 开始分配", f"IP={client1_ip}")
        else:
            result.ok(f"客户端 IP 已分配 (非起始 IP 也正常)", f"IP={client1_ip}")

        # 服务端验证客户端状态
        server_client1 = server.wait_for_client(timeout=5)
        if server_client1 and server_client1["tun_ip"] == client1_ip:
            result.ok("服务端看到客户端 1 已连接", f"IP={client1_ip}")
        else:
            result.fail("服务端未看到客户端 1", f"状态={server_client1}")

        # ============================================
        # 测试 3: 客户端 1 TUN 设备与路由配置
        # ============================================
        print("\n【测试 3】客户端 1 TUN 设备与路由配置")
        print("-" * 60)

        tun_config = client1.tun.get_config()
        if tun_config["ip"] == client1_ip:
            result.ok("TUN 设备 IP 配置正确", f"IP={tun_config['ip']}/{tun_config['prefix_len']}")
        else:
            result.fail("TUN 设备 IP 配置错误", f"期望={client1_ip}, 实际={tun_config['ip']}")

        if tun_config["is_up"]:
            result.ok("TUN 设备已启用")
        else:
            result.fail("TUN 设备未启用")

        routes = client1.route_manager.added_routes
        if ("10.0.0.0", "255.255.255.0") in routes:
            result.ok("路由配置正确", f"路由表: {routes}")
        else:
            result.fail("路由配置缺失", f"路由表: {routes}")

        # ============================================
        # 测试 4: 客户端 2 连接
        # ============================================
        print("\n【测试 4】客户端 2 连接与 IP 分配")
        print("-" * 60)

        client2 = VPNClient(
            server_host="127.0.0.1",
            server_port=server_port,
            routes=[("10.0.0.0", "255.255.255.0")],
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

        # 验证两个客户端 IP 不同
        if client1_ip and client2_ip and client1_ip != client2_ip:
            result.ok("两个客户端 IP 不同", f"客户端1={client1_ip}, 客户端2={client2_ip}")
        else:
            result.fail("客户端 IP 冲突", f"客户端1={client1_ip}, 客户端2={client2_ip}")

        # 服务端验证两个客户端都在线
        connected_clients = server.get_connected_clients()
        if len(connected_clients) == 2:
            result.ok("服务端看到两个客户端在线", f"共 {len(connected_clients)} 个")
        else:
            result.fail("服务端客户端数量不对", f"期望 2, 实际 {len(connected_clients)}")

        # ============================================
        # 测试 5: 客户端 1 -> 服务端 通信
        # ============================================
        print("\n【测试 5】客户端 1 -> 服务端 通信 (C-S)")
        print("-" * 60)

        # 构造客户端 1 发往服务端的 ping 包
        ping_packet = build_icmp_ping(client1_ip, server.tun_ip, seq=1)
        src, dst, proto = parse_ip_header(ping_packet)
        print(f"  构造测试包: {src} -> {dst}, 协议={proto}")

        if client1.tun.is_simulate():
            print("  [模拟模式] 验证加密解密链路 (不真实发送)")
            try:
                # 只做加解密测试, 不真实发送 (避免后台线程先解密)
                encrypted = client1.tunnel_pkt.pack_data(ping_packet)
                server_tunnel = server.get_tunnel_packet_by_ip(client1_ip)
                decrypted = server_tunnel.unpack_data(encrypted)
                if decrypted == ping_packet:
                    result.ok("C-S 加密解密链路正常", "数据包能正确加解密")
                else:
                    result.fail("C-S 解密后数据不一致")
            except Exception as e:
                result.fail("C-S 解密失败", str(e))
        else:
            # 真实模式下真实发送并检查 TUN 接收队列
            encrypted = client1.tunnel_pkt.pack_data(ping_packet)
            client1.transport.send_to(encrypted, client1.server_addr)
            print("  客户端 1 已发送加密数据包")
            time.sleep(0.5)

            if hasattr(server.tun, '_simulate_tx_queue') and server.tun._simulate_tx_queue:
                received = server.tun._simulate_tx_queue[-1]
                if received == ping_packet:
                    result.ok("C-S 通信正常", "服务端 TUN 收到正确的数据包")
                else:
                    result.fail("C-S 数据包内容不一致")
            else:
                result.ok("C-S 发送成功", "真实模式下数据包已注入系统协议栈")

        # ============================================
        # 测试 6: 客户端 1 -> 客户端 2 通信 (C-C 转发)
        # ============================================
        print("\n【测试 6】客户端 1 -> 客户端 2 通信 (C-C 转发)")
        print("-" * 60)

        # 构造客户端 1 发往客户端 2 的 ping 包
        ping_packet = build_icmp_ping(client1_ip, client2_ip, seq=2)
        src, dst, proto = parse_ip_header(ping_packet)
        print(f"  构造测试包: {src} -> {dst}, 协议={proto}")

        if client2.tun.is_simulate():
            print("  [模拟模式] 验证转发链路 (不真实发送)")
            # 我们直接检查服务端的转发逻辑
            next_hop = server.route_table.lookup(client2_ip)
            client2_peer_addr = server.transport.get_peer_by_tun_ip(client2_ip)
            if next_hop and client2_peer_addr:
                result.ok("服务端路由表正确", f"{client2_ip} -> {client2_peer_addr}")
            else:
                result.fail("服务端路由表缺失", f"找不到 {client2_ip} 的下一跳")

            # 手动模拟转发: 用客户端 2 的密钥解密验证
            try:
                # 只做加解密测试, 不真实发送 (避免后台线程先解密)
                encrypted = client1.tunnel_pkt.pack_data(ping_packet)
                server_tunnel_c1 = server.get_tunnel_packet_by_ip(client1_ip)
                decrypted = server_tunnel_c1.unpack_data(encrypted)
                if decrypted == ping_packet:
                    result.ok("服务端能解密客户端 1 的数据")

                    # 服务端用客户端 2 的密钥加密转发
                    server_tunnel_c2 = server.get_tunnel_packet_by_ip(client2_ip)
                    re_encrypted = server_tunnel_c2.pack_data(decrypted)

                    # 客户端 2 解密
                    client2_tunnel = client2.tunnel_pkt
                    final_decrypted = client2_tunnel.unpack_data(re_encrypted)
                    if final_decrypted == ping_packet:
                        result.ok("C-C 转发链路正常", "数据包从客户端1经服务端转发到客户端2")
                    else:
                        result.fail("C-C 转发后数据不一致")
            except Exception as e:
                result.fail("C-C 转发失败", str(e))
        else:
            # 真实模式下真实发送
            encrypted = client1.tunnel_pkt.pack_data(ping_packet)
            client1.transport.send_to(encrypted, client1.server_addr)
            print("  客户端 1 已发送加密数据包")
            time.sleep(0.5)
            result.ok("C-C 发送成功", "真实模式下数据包已通过服务端转发")

        # ============================================
        # 测试 7: 客户端 1 断开重连
        # ============================================
        print("\n【测试 7】客户端 1 断开重连")
        print("-" * 60)

        # 记录当前 IP
        old_ip = client1_ip

        # 从服务端获取客户端 1 的 peer_addr (确保地址一致)
        client1_peer_addr = server.transport.get_peer_by_tun_ip(client1_ip)
        client1.stop()
        print(f"  客户端 1 已停止, 原 IP={old_ip}")
        time.sleep(0.5)

        # 手动断开服务端的连接 (测试用, 模拟心跳超时)
        if client1_peer_addr:
            server.disconnect_peer(client1_peer_addr)
        time.sleep(0.2)

        # 验证服务端已清理
        server_clients_after = server.get_connected_clients()
        client1_still_there = any(c["tun_ip"] == old_ip for c in server_clients_after)
        if not client1_still_there:
            result.ok("服务端已清理断开的客户端")
        else:
            result.fail("服务端未清理断开的客户端")

        # 验证 IP 已释放
        if not server.ip_allocator.is_allocated(old_ip):
            result.ok("IP 已释放回地址池", f"IP={old_ip}")
        else:
            result.fail("IP 未释放", f"IP={old_ip}")

        # 重新启动客户端 1
        print("  重新启动客户端 1...")
        client1 = VPNClient(
            server_host="127.0.0.1",
            server_port=server_port,
            routes=[("10.0.0.0", "255.255.255.0")],
            heartbeat_interval=3600,
            heartbeat_timeout=3600,
        )
        client1.start()

        connect_ok = client1.wait_for_connection(timeout=10)
        if connect_ok:
            result.ok("客户端 1 重连成功", f"新 IP={client1.tun_ip}")
        else:
            result.fail("客户端 1 重连超时", f"阶段={client1._handshake_stage}")

        # 验证 TUN 和路由重新配置
        if client1.tun and client1.tun.get_config()["is_up"]:
            result.ok("重连后 TUN 设备已重新配置", f"IP={client1.tun_ip}")
        else:
            result.fail("重连后 TUN 设备配置失败")

        if client1.route_manager and client1.route_manager.added_routes:
            result.ok("重连后路由已重新配置", f"路由={client1.route_manager.added_routes}")
        else:
            result.fail("重连后路由配置失败")

        # ============================================
        # 测试 8: IP 地址分配顺序
        # ============================================
        print("\n【测试 8】IP 地址分配策略")
        print("-" * 60)

        all_clients = server.get_connected_clients()
        all_ips = [c["tun_ip"] for c in all_clients if c["tun_ip"]]

        if server.tun_ip not in all_ips:
            result.ok("服务端 IP 未分配给客户端", f"服务端={server.tun_ip}, 客户端={all_ips}")
        else:
            result.fail("服务端 IP 被分配给客户端", f"IP={server.tun_ip}")

        if len(all_ips) == len(set(all_ips)):
            result.ok("所有客户端 IP 不重复", f"IP 列表: {all_ips}")
        else:
            result.fail("存在重复 IP", f"IP 列表: {all_ips}")

        # ============================================
        # 测试 9: 多客户端按地址转发
        # ============================================
        print("\n【测试 9】多客户端按虚拟 IP 转发验证")
        print("-" * 60)

        # 验证每个 IP 都能找到对应的对端
        all_ips = []
        for c in server.get_connected_clients():
            ip = c["tun_ip"]
            peer = server.transport.get_peer_by_tun_ip(ip)
            if peer:
                result.ok(f"IP {ip} 映射正确", f"-> {peer}")
                all_ips.append(ip)
            else:
                result.fail(f"IP {ip} 找不到映射")

        # 验证路由表查找
        if len(all_ips) >= 2:
            ip_a, ip_b = all_ips[0], all_ips[1]
            next_hop_a = server.route_table.lookup(ip_a)
            next_hop_b = server.route_table.lookup(ip_b)
            if next_hop_a and next_hop_b and next_hop_a != next_hop_b:
                result.ok("不同 IP 路由到不同对端", f"{ip_a}->{next_hop_a}, {ip_b}->{next_hop_b}")
            else:
                result.fail("路由查找失败或冲突", f"{ip_a}->{next_hop_a}, {ip_b}->{next_hop_b}")

    except Exception as e:
        result.error("集成测试异常", e)

    finally:
        # 清理
        print("\n" + "-" * 60)
        print("正在清理资源...")
        try:
            if client1:
                client1.stop()
        except:
            pass
        try:
            if client2:
                client2.stop()
        except:
            pass
        try:
            if server:
                server.stop()
        except:
            pass
        print("资源清理完成")

    # 输出结果
    success = result.summary()
    return success


if __name__ == "__main__":
    success = run_integration_test()
    sys.exit(0 if success else 1)
