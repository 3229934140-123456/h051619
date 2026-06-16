import os
import struct
import subprocess
import sys
import platform

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False


class TunDevice:
    """
    TUN 虚拟网卡设备

    工作原理:
    - TUN 设备工作在 OSI 第三层 (网络层), 直接读写 IP 数据包
    - 程序打开 /dev/net/tun 设备文件, 通过 ioctl 将其配置为 TUN 模式
    - 操作系统向 TUN 网卡发送的 IP 包, 可以被程序通过 read() 读到
    - 程序通过 write() 写入的 IP 包, 会被操作系统当作从网卡收到的包处理

    数据流向:
    本机应用 -> 操作系统 -> 路由表 -> TUN 设备 -> 本程序 read()
    本程序 write() -> TUN 设备 -> 操作系统 -> 路由表 -> 本机应用
    """

    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    TUNSETIFF = 0x400454CA

    def __init__(self, name="tun0", ip="10.0.0.1", netmask="255.255.255.0", mtu=1500):
        """
        初始化 TUN 设备

        Args:
            name: 网卡名称, 如 tun0
            ip: 网卡 IP 地址
            netmask: 子网掩码
            mtu: 最大传输单元
        """
        self.name = name
        self.ip = ip
        self.netmask = netmask
        self.mtu = mtu
        self.fd = None
        self._simulate_mode = False

    def open(self):
        """
        打开并配置 TUN 设备

        步骤:
        1. 打开 /dev/net/tun 字符设备
        2. 通过 ioctl 调用 TUNSETIFF 设置设备类型为 TUN
        3. 配置 IP 地址和子网掩码
        4. 启用网卡
        """
        if platform.system() != "Linux" or not HAS_FCNTL:
            print(f"[TUN] [模拟] 设备 {self.name} 已启动, IP={self.ip}/{self._prefix_len()}, MTU={self.mtu}")
            self._simulate_mode = True
            self._simulate_rx_queue = []
            self._simulate_tx_queue = []
            self._is_up = True
            return

        try:
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
        except FileNotFoundError:
            print("[错误] 找不到 /dev/net/tun, 请确保内核支持 TUN 模块")
            raise
        except PermissionError:
            print("[错误] 权限不足, 请以 root 身份运行")
            raise

        ifr = struct.pack("16sH", self.name.encode("utf-8"), self.IFF_TUN | self.IFF_NO_PI)
        fcntl.ioctl(self.fd, self.TUNSETIFF, ifr)

        self._configure_ip()
        self._set_mtu()
        self._up()
        self._is_up = True

        print(f"[TUN] 设备 {self.name} 已启动, IP={self.ip}/{self._prefix_len()}, MTU={self.mtu}")

    def _configure_ip(self):
        """配置 IP 地址和子网掩码"""
        subprocess.run(
            ["ip", "addr", "add", f"{self.ip}/{self._prefix_len()}", "dev", self.name],
            check=True,
            capture_output=True,
        )

    def _set_mtu(self):
        """设置 MTU"""
        subprocess.run(
            ["ip", "link", "set", "dev", self.name, "mtu", str(self.mtu)],
            check=True,
            capture_output=True,
        )

    def _up(self):
        """启用网卡"""
        subprocess.run(
            ["ip", "link", "set", "dev", self.name, "up"],
            check=True,
            capture_output=True,
        )

    def _prefix_len(self):
        """将点分十进制子网掩码转换为前缀长度"""
        parts = [int(x) for x in self.netmask.split(".")]
        return sum(bin(x).count("1") for x in parts)

    def read(self):
        """
        从 TUN 设备读取一个 IP 数据包

        Returns:
            bytes: 原始 IP 数据包
        """
        if self._simulate_mode:
            while True:
                if self._simulate_rx_queue:
                    return self._simulate_rx_queue.pop(0)
                import time
                time.sleep(0.01)

        return os.read(self.fd, self.mtu + 100)

    def write(self, packet):
        """
        向 TUN 设备写入一个 IP 数据包

        Args:
            packet: 原始 IP 数据包 (bytes)
        """
        if self._simulate_mode:
            self._simulate_tx_queue.append(packet)
            return

        os.write(self.fd, packet)

    def close(self):
        """关闭 TUN 设备"""
        if self._simulate_mode:
            print(f"[TUN] [模拟] 设备 {self.name} 已关闭")
            self._is_up = False
            return

        if self.fd:
            os.close(self.fd)
            self.fd = None
            self._is_up = False
            print(f"[TUN] 设备 {self.name} 已关闭")

    def get_config(self) -> dict:
        """
        获取 TUN 设备配置信息

        Returns:
            dict: 包含 name, ip, netmask, prefix_len, mtu, is_up, is_simulate 的字典
        """
        return {
            "name": self.name,
            "ip": self.ip,
            "netmask": self.netmask,
            "prefix_len": self._prefix_len(),
            "mtu": self.mtu,
            "is_up": getattr(self, "_is_up", False),
            "is_simulate": self._simulate_mode,
        }

    def inject_rx_packet(self, packet: bytes):
        """
        向 TUN 设备的接收队列注入一个 IP 包 (模拟本机应用发出的包)

        Args:
            packet: 原始 IP 数据包
        """
        if self._simulate_mode:
            self._simulate_rx_queue.append(packet)
        else:
            raise RuntimeError("真实模式下不能注入数据包, 请通过系统协议栈发送")

    def get_tx_packets(self, clear: bool = True) -> list:
        """
        获取 TUN 设备发送队列中的所有包 (模拟模式下检查是否收到包)

        Args:
            clear: 是否清空队列

        Returns:
            list: 数据包列表
        """
        if not self._simulate_mode:
            return []
        packets = list(self._simulate_tx_queue)
        if clear:
            self._simulate_tx_queue.clear()
        return packets

    def is_simulate(self) -> bool:
        """是否为模拟模式"""
        return self._simulate_mode

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def parse_ip_header(packet):
    """
    解析 IP 首部, 返回源地址和目的地址

    IP 首部格式 (IPv4):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    if len(packet) < 20:
        return None, None

    src_ip = ".".join(str(b) for b in packet[12:16])
    dst_ip = ".".join(str(b) for b in packet[16:20])
    protocol = packet[9]

    return src_ip, dst_ip, protocol
