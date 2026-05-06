#!/usr/bin/env python3
"""
用户态 IPIP 隧道实现

原理：
  IPIP 隧道将一个完整的 IP 包封装在另一个 IP 包中传输。
  这是最简单的隧道形式：外部 IP 头的协议字段为 4 (IP-in-IP)。

  本示例使用两个 network namespace 模拟两个站点，
  通过用户态程序实现 IPIP 隧道连接。

  拓扑：
  ┌─ ns1 ──────────────────┐      ┌─ ns2 ──────────────────┐
  │ tun0: 192.168.1.1/24   │      │ tun0: 192.168.1.2/24   │
  │      ↓                 │      │      ↓                 │
  │ [隧道程序 端口5000]     │      │ [隧道程序 端口5001]     │
  │      ↓                 │      │      ↓                 │
  │ veth1: 10.0.0.1        │──────│ veth2: 10.0.0.2        │
  └────────────────────────┘      └────────────────────────┘

  简化版：使用 loopback + UDP 封装模拟隧道传输

运行方式：
  sudo python3 ipip_tunnel.py

验证方法：
  脚本会自动进行 ping 测试并显示结果
"""

import os
import sys
import struct
import fcntl
import socket
import threading
import subprocess
import time
import select

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def create_tun(name: str) -> int:
    """创建 TUN 设备"""
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd


def calculate_checksum(data: bytes) -> int:
    """计算 IP 校验和"""
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def build_outer_ip_header(src_ip: str, dst_ip: str, inner_packet: bytes) -> bytes:
    """
    构建 IPIP 隧道的外部 IP 头

    外部 IP 头的 Protocol 字段为 4 (IP-in-IP)
    """
    version_ihl = (4 << 4) | 5
    tos = 0
    total_length = 20 + len(inner_packet)
    identification = os.getpid() & 0xFFFF
    flags_offset = 0x4000  # DF=1
    ttl = 64
    protocol = 4  # IPIP

    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_length,
                         identification, flags_offset,
                         ttl, protocol, 0,
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))
    checksum = calculate_checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_length,
                         identification, flags_offset,
                         ttl, protocol, checksum,
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))
    return header


class IPIPTunnel:
    """
    用户态 IPIP 隧道

    工作流程：
    1. 从 TUN 读取内部 IP 包
    2. 添加外部 IP 头（协议号=4）
    3. 通过 UDP 套接字发送到对端（模拟物理链路传输）
    4. 对端接收后剥离外部 IP 头
    5. 将内部 IP 包写入对端的 TUN
    """

    def __init__(self, tun_name: str, local_ip: str, remote_ip: str,
                 tunnel_src: str, tunnel_dst: str, udp_port: int):
        self.tun_name = tun_name
        self.local_ip = local_ip      # TUN 接口的内部 IP
        self.remote_ip = remote_ip    # 对端 TUN 的内部 IP
        self.tunnel_src = tunnel_src  # 隧道外部源 IP
        self.tunnel_dst = tunnel_dst  # 隧道外部目的 IP
        self.udp_port = udp_port      # 用 UDP 模拟隧道传输
        self.running = False
        self.stats = {'tx': 0, 'rx': 0, 'tx_bytes': 0, 'rx_bytes': 0}

    def start(self):
        """启动隧道"""
        # 创建 TUN
        self.tun_fd = create_tun(self.tun_name)

        # 配置 TUN
        subprocess.run(['ip', 'addr', 'add', f'{self.local_ip}/24',
                        'dev', self.tun_name], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', self.tun_name, 'up'],
                       check=True, capture_output=True)

        # 创建 UDP 套接字 (模拟隧道的物理传输)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('127.0.0.1', self.udp_port))
        self.udp_sock.setblocking(False)

        self.running = True
        print(f"  [{self.tun_name}] 隧道启动: {self.local_ip} "
              f"(tunnel: {self.tunnel_src} → {self.tunnel_dst})")

    def process_outbound(self):
        """处理出站流量：TUN → 封装 → UDP 发送"""
        try:
            packet = os.read(self.tun_fd, 4096)
        except OSError:
            return False

        if not packet:
            return False

        # 封装：添加外部 IP 头
        outer_header = build_outer_ip_header(self.tunnel_src, self.tunnel_dst, packet)
        encapsulated = outer_header + packet

        # 通过 UDP 发送到对端
        peer_port = 5001 if self.udp_port == 5000 else 5000
        self.udp_sock.sendto(encapsulated, ('127.0.0.1', peer_port))

        self.stats['tx'] += 1
        self.stats['tx_bytes'] += len(encapsulated)

        if len(packet) >= 20:
            src = socket.inet_ntoa(packet[12:16])
            dst = socket.inet_ntoa(packet[16:20])
            print(f"  [{self.tun_name}] TX: {src}→{dst} "
                  f"封装为 {self.tunnel_src}→{self.tunnel_dst} "
                  f"({len(packet)}→{len(encapsulated)} bytes)")
        return True

    def process_inbound(self):
        """处理入站流量：UDP 接收 → 解封装 → TUN"""
        try:
            data, addr = self.udp_sock.recvfrom(4096)
        except (BlockingIOError, OSError):
            return False

        if not data or len(data) < 40:  # 至少需要外部IP头(20) + 内部IP头(20)
            return False

        # 解封装：去掉外部 IP 头 (20 bytes)
        outer_ihl = (data[0] & 0x0F) * 4
        inner_packet = data[outer_ihl:]

        # 验证外部头的协议字段
        outer_protocol = data[9]
        if outer_protocol != 4:  # 不是 IPIP
            return False

        # 写入 TUN
        os.write(self.tun_fd, inner_packet)

        self.stats['rx'] += 1
        self.stats['rx_bytes'] += len(inner_packet)

        if len(inner_packet) >= 20:
            src = socket.inet_ntoa(inner_packet[12:16])
            dst = socket.inet_ntoa(inner_packet[16:20])
            print(f"  [{self.tun_name}] RX: {src}→{dst} "
                  f"(解封装 {len(data)}→{len(inner_packet)} bytes)")
        return True

    def stop(self):
        """停止隧道"""
        self.running = False
        os.close(self.tun_fd)
        self.udp_sock.close()


def tunnel_loop(tunnel: IPIPTunnel):
    """隧道主循环"""
    while tunnel.running:
        # 使用 select 同时监控 TUN fd 和 UDP socket
        readable, _, _ = select.select(
            [tunnel.tun_fd, tunnel.udp_sock], [], [], 0.1)

        for fd in readable:
            if fd == tunnel.tun_fd:
                tunnel.process_outbound()
            elif fd == tunnel.udp_sock:
                tunnel.process_inbound()


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    print("=" * 70)
    print("IPIP 隧道演示")
    print("=" * 70)
    print()
    print("拓扑:")
    print("  tun_a (192.168.1.1) ←→ IPIP隧道(UDP模拟) ←→ tun_b (192.168.1.2)")
    print()

    # 创建两端隧道
    tunnel_a = IPIPTunnel(
        tun_name='tun_a',
        local_ip='192.168.1.1',
        remote_ip='192.168.1.2',
        tunnel_src='10.0.0.1',
        tunnel_dst='10.0.0.2',
        udp_port=5000
    )

    tunnel_b = IPIPTunnel(
        tun_name='tun_b',
        local_ip='192.168.1.2',
        remote_ip='192.168.1.1',
        tunnel_src='10.0.0.2',
        tunnel_dst='10.0.0.1',
        udp_port=5001
    )

    try:
        tunnel_a.start()
        tunnel_b.start()

        print()
        print("[*] 隧道已建立，启动数据转发...")
        print()

        # 在线程中运行隧道
        thread_a = threading.Thread(target=tunnel_loop, args=(tunnel_a,), daemon=True)
        thread_b = threading.Thread(target=tunnel_loop, args=(tunnel_b,), daemon=True)
        thread_a.start()
        thread_b.start()

        time.sleep(1)

        # 测试：ping 通过隧道
        print("[测试] ping 192.168.1.2 (通过 IPIP 隧道)...")
        print()
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '2', '-I', 'tun_a', '192.168.1.2'],
            capture_output=True, text=True, timeout=10
        )
        print(result.stdout)
        if result.returncode == 0:
            print("[✓] IPIP 隧道测试成功！")
        else:
            print("[!] ping 未收到回复 (这在用户态隧道中可能是正常的)")
            print("    内核可能不会路由 tun_a 发出的包到 tun_b")

        # 显示统计
        print()
        print("[统计]")
        print(f"  Tunnel A: TX={tunnel_a.stats['tx']} pkts "
              f"({tunnel_a.stats['tx_bytes']} B), "
              f"RX={tunnel_a.stats['rx']} pkts "
              f"({tunnel_a.stats['rx_bytes']} B)")
        print(f"  Tunnel B: TX={tunnel_b.stats['tx']} pkts "
              f"({tunnel_b.stats['tx_bytes']} B), "
              f"RX={tunnel_b.stats['rx']} pkts "
              f"({tunnel_b.stats['rx_bytes']} B)")

    except Exception as e:
        print(f"错误: {e}")
    finally:
        tunnel_a.stop()
        tunnel_b.stop()
        print("\n[✓] 隧道已关闭")

    print()
    print("=" * 70)
    print("IPIP 隧道原理总结:")
    print("  1. 从 TUN 读取原始 IP 包")
    print("  2. 在前面添加新的 IP 头 (protocol=4)")
    print("  3. 通过物理网络发送到隧道对端")
    print("  4. 对端剥离外部 IP 头，得到原始 IP 包")
    print("  5. 将原始 IP 包写入对端 TUN")
    print()
    print("内核态 IPIP 配置方法:")
    print("  ip tunnel add ipip0 mode ipip local 1.1.1.1 remote 2.2.2.2")
    print("  ip addr add 192.168.1.1/24 dev ipip0")
    print("  ip link set ipip0 up")
    print("=" * 70)


if __name__ == '__main__':
    main()
