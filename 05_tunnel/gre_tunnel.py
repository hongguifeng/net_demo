#!/usr/bin/env python3
"""
用户态 GRE 隧道实现

原理：
  GRE (Generic Routing Encapsulation) 是比 IPIP 更灵活的隧道协议。
  它在外部 IP 头和内部载荷之间增加了 GRE 头，支持：
  - 多种内部协议 (IPv4, IPv6, Ethernet 等)
  - Key 字段 (多路复用/租户隔离)
  - Sequence Number (排序)
  - Checksum (完整性校验)

  封装格式:
  ┌──────────────┬──────────────┬──────────────┬──────────────┐
  │ Outer IP     │ GRE Header   │ Inner IP     │ Payload      │
  │ Proto=47     │ 4-16 bytes   │              │              │
  └──────────────┴──────────────┴──────────────┴──────────────┘

  GRE Header (简化版, 4 bytes):
  ┌─┬─┬─┬─┬──────────────┬─────┬────────────────────────────────┐
  │C│ │K│S│  Reserved0    │ Ver │       Protocol Type            │
  └─┴─┴─┴─┴──────────────┴─────┴────────────────────────────────┘
  C=Checksum present, K=Key present, S=Sequence present

运行方式：
  sudo python3 gre_tunnel.py

验证方法：
  脚本会自动进行封装/解封装测试并验证正确性
"""

import os
import sys
import struct
import fcntl
import socket
import threading
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
    """IP/GRE 校验和"""
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


class GREHeader:
    """
    GRE 头部构造与解析

    标志位：
    - C (bit 0): Checksum Present
    - K (bit 2): Key Present
    - S (bit 3): Sequence Number Present
    - Ver (bits 13-15): 版本号 (必须为 0)

    Protocol Type: 内部协议类型
    - 0x0800: IPv4
    - 0x86DD: IPv6
    - 0x6558: Ethernet (用于 NVGRE)
    """

    def __init__(self, protocol: int = 0x0800, key: int = None,
                 sequence: int = None, checksum: bool = False):
        self.protocol = protocol
        self.key = key
        self.sequence = sequence
        self.use_checksum = checksum

    def encode(self, payload: bytes = b'') -> bytes:
        """编码 GRE 头"""
        flags = 0

        if self.use_checksum:
            flags |= 0x8000  # C bit
        if self.key is not None:
            flags |= 0x2000  # K bit
        if self.sequence is not None:
            flags |= 0x1000  # S bit

        # 基本头 (4 bytes): Flags(2) + Protocol(2)
        header = struct.pack('!HH', flags, self.protocol)

        # 可选字段
        if self.use_checksum:
            # 先放占位符，后面计算
            header += struct.pack('!HH', 0, 0)  # Checksum + Reserved1

        if self.key is not None:
            header += struct.pack('!I', self.key)

        if self.sequence is not None:
            header += struct.pack('!I', self.sequence)

        # 计算校验和 (如果需要)
        if self.use_checksum:
            full_data = header + payload
            chk = calculate_checksum(full_data)
            # 将校验和填入 (偏移 4 bytes，在 flags+protocol 之后)
            header = header[:4] + struct.pack('!HH', chk, 0) + header[8:]

        return header

    @staticmethod
    def decode(data: bytes) -> tuple:
        """
        解码 GRE 头

        返回: (GREHeader 对象, 偏移量)
        """
        if len(data) < 4:
            raise ValueError("GRE 头太短")

        flags, protocol = struct.unpack('!HH', data[:4])
        offset = 4

        has_checksum = bool(flags & 0x8000)
        has_key = bool(flags & 0x2000)
        has_sequence = bool(flags & 0x1000)

        checksum_val = None
        key = None
        sequence = None

        if has_checksum:
            checksum_val = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 4  # checksum(2) + reserved(2)

        if has_key:
            key = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4

        if has_sequence:
            sequence = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4

        gre = GREHeader(protocol=protocol, key=key, sequence=sequence,
                        checksum=has_checksum)
        return gre, offset


class GRETunnel:
    """
    GRE 隧道实现

    相比 IPIP 的改进：
    - Key 字段支持多隧道复用 (类似 VLAN)
    - Sequence 字段防止包乱序
    - Checksum 保证数据完整性
    """

    def __init__(self, tun_name: str, local_ip: str,
                 tunnel_src: str, tunnel_dst: str,
                 udp_port: int, gre_key: int = None):
        self.tun_name = tun_name
        self.local_ip = local_ip
        self.tunnel_src = tunnel_src
        self.tunnel_dst = tunnel_dst
        self.udp_port = udp_port
        self.gre_key = gre_key
        self.sequence = 0
        self.running = False
        self.stats = {'tx': 0, 'rx': 0}

    def start(self):
        """启动 GRE 隧道"""
        self.tun_fd = create_tun(self.tun_name)

        import subprocess
        subprocess.run(['ip', 'addr', 'add', f'{self.local_ip}/24',
                        'dev', self.tun_name], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', self.tun_name, 'up'],
                       check=True, capture_output=True)

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('127.0.0.1', self.udp_port))
        self.udp_sock.setblocking(False)

        self.running = True

    def encapsulate(self, inner_packet: bytes) -> bytes:
        """
        GRE 封装

        内部包 → GRE头 → 外部IP头
        """
        # 构造 GRE 头
        gre = GREHeader(
            protocol=0x0800,        # 内部是 IPv4
            key=self.gre_key,       # 隧道标识
            sequence=self.sequence, # 序列号
            checksum=True           # 启用校验和
        )
        self.sequence += 1

        gre_header = gre.encode(inner_packet)

        # 构造外部 IP 头 (protocol=47 for GRE)
        outer_payload = gre_header + inner_packet
        total_length = 20 + len(outer_payload)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                0x45, 0, total_length,
                                self.sequence & 0xFFFF, 0x4000,
                                64, 47, 0,  # protocol=47 (GRE)
                                socket.inet_aton(self.tunnel_src),
                                socket.inet_aton(self.tunnel_dst))
        checksum = calculate_checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                0x45, 0, total_length,
                                self.sequence & 0xFFFF, 0x4000,
                                64, 47, checksum,
                                socket.inet_aton(self.tunnel_src),
                                socket.inet_aton(self.tunnel_dst))

        return ip_header + outer_payload

    def decapsulate(self, data: bytes) -> bytes:
        """
        GRE 解封装

        外部IP头 → GRE头 → 内部包
        """
        if len(data) < 24:  # 最小: IP(20) + GRE(4)
            return b''

        # 剥离外部 IP 头
        outer_ihl = (data[0] & 0x0F) * 4
        outer_protocol = data[9]

        if outer_protocol != 47:  # 不是 GRE
            return b''

        gre_data = data[outer_ihl:]

        # 解析 GRE 头
        gre, gre_offset = GREHeader.decode(gre_data)

        # 验证 Key
        if self.gre_key is not None and gre.key != self.gre_key:
            print(f"    [!] Key 不匹配: 期望={self.gre_key}, 实际={gre.key}")
            return b''

        # 返回内部包
        return gre_data[gre_offset:]

    def process(self):
        """处理隧道数据"""
        readable, _, _ = select.select(
            [self.tun_fd, self.udp_sock], [], [], 0.1)

        for fd in readable:
            if fd == self.tun_fd:
                # 出站: TUN → GRE封装 → UDP
                try:
                    packet = os.read(self.tun_fd, 4096)
                    if packet:
                        encapsulated = self.encapsulate(packet)
                        peer_port = 6001 if self.udp_port == 6000 else 6000
                        self.udp_sock.sendto(encapsulated, ('127.0.0.1', peer_port))
                        self.stats['tx'] += 1
                except OSError:
                    pass

            elif fd == self.udp_sock:
                # 入站: UDP → GRE解封装 → TUN
                try:
                    data, _ = self.udp_sock.recvfrom(4096)
                    inner = self.decapsulate(data)
                    if inner:
                        os.write(self.tun_fd, inner)
                        self.stats['rx'] += 1
                except (BlockingIOError, OSError):
                    pass

    def stop(self):
        """停止隧道"""
        self.running = False
        os.close(self.tun_fd)
        self.udp_sock.close()


def demo_gre_header():
    """演示 GRE 头部编解码"""
    print("=" * 70)
    print("GRE 头部编解码演示")
    print("=" * 70)
    print()

    # 测试 1: 基本 GRE 头 (无可选字段)
    print("[测试 1] 基本 GRE 头 (仅 Flags + Protocol)")
    gre1 = GREHeader(protocol=0x0800)
    encoded1 = gre1.encode()
    print(f"  编码: {encoded1.hex()} ({len(encoded1)} bytes)")

    decoded1, offset1 = GREHeader.decode(encoded1)
    print(f"  解码: protocol=0x{decoded1.protocol:04x}, offset={offset1}")
    print(f"  验证: {'✓' if decoded1.protocol == 0x0800 else '✗'}")
    print()

    # 测试 2: 带 Key 的 GRE 头
    print("[测试 2] 带 Key 的 GRE 头 (用于多租户隔离)")
    gre2 = GREHeader(protocol=0x0800, key=12345)
    encoded2 = gre2.encode()
    print(f"  编码: {encoded2.hex()} ({len(encoded2)} bytes)")

    decoded2, offset2 = GREHeader.decode(encoded2)
    print(f"  解码: protocol=0x{decoded2.protocol:04x}, key={decoded2.key}, offset={offset2}")
    print(f"  验证: {'✓' if decoded2.key == 12345 else '✗'}")
    print()

    # 测试 3: 完整 GRE 头 (Checksum + Key + Sequence)
    print("[测试 3] 完整 GRE 头 (C+K+S)")
    payload = b'\x45\x00\x00\x3c' + b'\x00' * 56  # 模拟 IP 包
    gre3 = GREHeader(protocol=0x0800, key=99999, sequence=42, checksum=True)
    encoded3 = gre3.encode(payload)
    print(f"  编码: {encoded3.hex()} ({len(encoded3)} bytes)")

    decoded3, offset3 = GREHeader.decode(encoded3)
    print(f"  解码: protocol=0x{decoded3.protocol:04x}, "
          f"key={decoded3.key}, seq={decoded3.sequence}")
    print(f"  验证: key={'✓' if decoded3.key == 99999 else '✗'}, "
          f"seq={'✓' if decoded3.sequence == 42 else '✗'}")
    print()


def demo_gre_tunnel():
    """演示 GRE 隧道数据转发"""
    import subprocess

    print("=" * 70)
    print("GRE 隧道数据转发演示")
    print("=" * 70)
    print()
    print("拓扑:")
    print("  gre_a (172.16.0.1) ←→ GRE隧道(Key=1001) ←→ gre_b (172.16.0.2)")
    print()

    tunnel_a = GRETunnel(
        tun_name='gre_a', local_ip='172.16.0.1',
        tunnel_src='10.0.0.1', tunnel_dst='10.0.0.2',
        udp_port=6000, gre_key=1001
    )

    tunnel_b = GRETunnel(
        tun_name='gre_b', local_ip='172.16.0.2',
        tunnel_src='10.0.0.2', tunnel_dst='10.0.0.1',
        udp_port=6001, gre_key=1001
    )

    try:
        tunnel_a.start()
        tunnel_b.start()
        print(f"  [✓] GRE 隧道 A 启动 (Key={tunnel_a.gre_key})")
        print(f"  [✓] GRE 隧道 B 启动 (Key={tunnel_b.gre_key})")
        print()

        # 在线程中运行隧道
        def run_tunnel(t):
            while t.running:
                t.process()

        thread_a = threading.Thread(target=run_tunnel, args=(tunnel_a,), daemon=True)
        thread_b = threading.Thread(target=run_tunnel, args=(tunnel_b,), daemon=True)
        thread_a.start()
        thread_b.start()

        time.sleep(1)

        # 测试
        print("[测试] ping 172.16.0.2 通过 GRE 隧道...")
        result = subprocess.run(
            ['ping', '-c', '3', '-W', '2', '-I', 'gre_a', '172.16.0.2'],
            capture_output=True, text=True, timeout=10
        )
        if result.stdout:
            print(result.stdout)

        print(f"\n[统计]")
        print(f"  Tunnel A: TX={tunnel_a.stats['tx']}, RX={tunnel_a.stats['rx']}")
        print(f"  Tunnel B: TX={tunnel_b.stats['tx']}, RX={tunnel_b.stats['rx']}")

    except Exception as e:
        print(f"  [!] 错误: {e}")
    finally:
        tunnel_a.stop()
        tunnel_b.stop()
        print("\n  [✓] GRE 隧道已关闭")


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    demo_gre_header()
    print()
    demo_gre_tunnel()

    print()
    print("=" * 70)
    print("GRE 隧道总结:")
    print("  - GRE 比 IPIP 更灵活，支持 Key/Sequence/Checksum")
    print("  - Key 字段用于多隧道复用 (类似 VLAN ID)")
    print("  - NVGRE 使用 GRE Key 的低 24 位作为 VSID (虚拟子网标识)")
    print("  - GRE over IPsec 是企业 VPN 的常见方案")
    print()
    print("内核态 GRE 配置:")
    print("  ip tunnel add gre1 mode gre local 1.1.1.1 remote 2.2.2.2 key 1001")
    print("  ip addr add 172.16.0.1/24 dev gre1")
    print("  ip link set gre1 up")
    print("=" * 70)


if __name__ == '__main__':
    main()
