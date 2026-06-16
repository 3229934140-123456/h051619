import socket
import struct
import subprocess
import platform
import ipaddress
from typing import Dict, Optional, Tuple


class RouteEntry:
    """路由表条目"""

    def __init__(self, network: str, netmask: str, gateway: str = None, interface: str = None):
        self.network = network
        self.netmask = netmask
        self.gateway = gateway
        self.interface = interface
        self._network_obj = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)

    def matches(self, ip: str) -> bool:
        """检查 IP 是否在该路由条目的网段内"""
        return ipaddress.IPv4Address(ip) in self._network_obj


class RouteTable:
    """
    路由表 - 管理 VPN 内部的路由转发

    工作原理:
    当服务端收到一个 IP 包时, 需要决定把它发给哪个客户端:
    1. 解析 IP 包的目的地址
    2. 查找路由表, 看哪个客户端负责这个目的网段
    3. 将数据包转发给对应的客户端

    这类似于路由器的工作方式, 但工作在用户空间。
    """

    def __init__(self):
        self.routes: list = []
        self.host_routes: Dict[str, Tuple[str, int]] = {}

    def add_route(self, network: str, netmask: str, peer_addr: Tuple[str, int]):
        """添加一条网段路由"""
        entry = RouteEntry(network, netmask)
        entry.peer_addr = peer_addr
        self.routes.append(entry)
        print(f"[路由] 添加路由: {network}/{netmask} -> {peer_addr}")

    def add_host_route(self, ip: str, peer_addr: Tuple[str, int]):
        """添加一条主机路由 (精确到单个 IP)"""
        self.host_routes[ip] = peer_addr
        print(f"[路由] 添加主机路由: {ip} -> {peer_addr}")

    def remove_peer_routes(self, peer_addr: Tuple[str, int]):
        """移除某个对端的所有路由"""
        self.routes = [r for r in self.routes if r.peer_addr != peer_addr]
        self.host_routes = {k: v for k, v in self.host_routes.items() if v != peer_addr}

    def lookup(self, dst_ip: str) -> Optional[Tuple[str, int]]:
        """
        路由查找 - 根据目的 IP 查找下一跳对端

        使用最长匹配原则: 优先匹配更精确 (前缀更长) 的路由
        """
        if dst_ip in self.host_routes:
            return self.host_routes[dst_ip]

        best_match = None
        best_prefix_len = -1

        for route in self.routes:
            if route.matches(dst_ip):
                prefix_len = route._network_obj.prefixlen
                if prefix_len > best_prefix_len:
                    best_match = route.peer_addr
                    best_prefix_len = prefix_len

        return best_match


class SystemRouteManager:
    """
    系统路由管理器 - 配置操作系统的路由表

    为什么需要配置系统路由:
    - TUN 设备只是一个虚拟网卡, 操作系统默认不会把流量发给它
    - 需要告诉操作系统: 哪些目的网段的流量应该走 TUN 设备
    - 这样应用程序发出的数据包才会被路由到 TUN 设备, 进而被 VPN 程序捕获

    工作流程:
    1. VPN 启动时, 添加路由规则, 将目标网段指向 TUN 网卡
    2. 应用程序发送数据包到目标网段
    3. 操作系统查路由表, 发现应该走 TUN 网卡
    4. 数据包被写入 TUN 设备, VPN 程序 read() 到它
    5. VPN 程序加密后通过物理网卡发给对端
    """

    def __init__(self, interface: str, simulate: bool = None):
        """
        初始化系统路由管理器

        Args:
            interface: 网络接口名称
            simulate: 是否使用模拟模式。None 表示自动检测 (非 Linux 系统自动进入模拟模式)
        """
        self.interface = interface
        self.added_routes = []
        if simulate is None:
            self.simulate = platform.system() != "Linux"
        else:
            self.simulate = simulate
        if self.simulate:
            print(f"[路由] 进入模拟模式, 不会实际修改系统路由表")

    def add_route(self, network: str, netmask: str) -> bool:
        """
        添加系统路由

        Args:
            network: 目标网络
            netmask: 子网掩码

        Returns:
            bool: 是否成功
        """
        if self.simulate:
            self.added_routes.append((network, netmask))
            print(f"[路由] [模拟] 已添加路由: {network}/{netmask} dev {self.interface}")
            return True

        try:
            result = subprocess.run(
                ["ip", "route", "add", f"{network}/{self._prefix_len(netmask)}", "dev", self.interface],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                self.added_routes.append((network, netmask))
                print(f"[路由] 已添加系统路由: {network}/{netmask} dev {self.interface}")
                return True
            else:
                print(f"[路由] 添加路由失败: {result.stderr.strip()}")
                return False
        except Exception as e:
            print(f"[路由] 添加路由异常: {e}")
            return False

    def remove_route(self, network: str, netmask: str) -> bool:
        """删除系统路由"""
        if self.simulate:
            print(f"[路由] [模拟] 已删除路由: {network}/{netmask} dev {self.interface}")
            return True

        try:
            result = subprocess.run(
                ["ip", "route", "del", f"{network}/{self._prefix_len(netmask)}", "dev", self.interface],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"[路由] 已删除系统路由: {network}/{netmask}")
                return True
            return False
        except Exception:
            return False

    def cleanup(self):
        """清理所有添加的路由"""
        for network, netmask in reversed(self.added_routes):
            self.remove_route(network, netmask)
        self.added_routes = []

    def _prefix_len(self, netmask: str) -> int:
        """子网掩码转前缀长度"""
        parts = [int(x) for x in netmask.split(".")]
        return sum(bin(x).count("1") for x in parts)


def ip_in_network(ip: str, network: str, netmask: str) -> bool:
    """
    检查 IP 是否在指定网段内

    原理: IP 地址和子网掩码做按位与运算, 结果等于网络地址则在网段内
    """
    try:
        net = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
        return ipaddress.IPv4Address(ip) in net
    except ValueError:
        return False


def get_network_address(ip: str, netmask: str) -> str:
    """计算网络地址"""
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(net.network_address)


class IPAllocator:
    """
    IP 地址分配器 - 为接入的客户端分配虚拟内网 IP

    服务端维护一个 IP 地址池, 客户端连接时分配一个 IP,
    断开时回收 IP。这样服务端就知道每个客户端对应哪个内网 IP,
    可以正确地转发数据包。
    """

    def __init__(self, network: str, netmask: str, exclude_ips: list = None):
        """
        初始化 IP 分配器

        Args:
            network: 网络地址
            netmask: 子网掩码
            exclude_ips: 需要排除的 IP 列表 (如服务端自身的 IP)
        """
        self.network = network
        self.netmask = netmask
        self.exclude_ips = set(exclude_ips or [])
        self._net = ipaddress.IPv4Network(f"{network}/{netmask}", strict=False)
        self._hosts = [str(ip) for ip in self._net.hosts() if str(ip) not in self.exclude_ips]
        self._allocated = set()
        self._alloc_map = {}
        if self.exclude_ips:
            print(f"[IP分配] 已排除 IP: {', '.join(self.exclude_ips)}")

    def allocate(self, peer_id: str) -> Optional[str]:
        """
        分配一个 IP 地址

        Args:
            peer_id: 客户端标识 (如地址元组)

        Returns:
            分配的 IP 地址, 分配失败返回 None
        """
        peer_key = str(peer_id)

        if peer_key in self._alloc_map:
            return self._alloc_map[peer_key]

        for ip in self._hosts:
            ip_str = str(ip)
            if ip_str not in self._allocated:
                self._allocated.add(ip_str)
                self._alloc_map[peer_key] = ip_str
                print(f"[IP分配] 为 {peer_id} 分配 IP: {ip_str}")
                return ip_str

        print("[IP分配] 地址池已耗尽")
        return None

    def release(self, peer_id: str):
        """释放 IP 地址"""
        peer_key = str(peer_id)
        if peer_key in self._alloc_map:
            ip = self._alloc_map.pop(peer_key)
            self._allocated.discard(ip)
            print(f"[IP分配] 释放 IP: {ip} (来自 {peer_id})")

    def get_ip(self, peer_id: str) -> Optional[str]:
        """获取已分配的 IP"""
        return self._alloc_map.get(str(peer_id))

    def is_allocated(self, ip: str) -> bool:
        """检查 IP 是否已分配"""
        return ip in self._allocated
