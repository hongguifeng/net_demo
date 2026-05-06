#!/usr/bin/env python3
"""
IP 数据包手动构造 - 不依赖内核协议栈，从零构建 IP 包

原理：
  使用 SOCK_RAW + IPPROTO_RAW 可以完全自定义 IP 头部。
  内核不会为我们填充任何字段，需要手动计算校验和。

  这让我们深入理解 IP 头部各字段的含义和作用。

运行方式：
  sudo python3 ip_packet.py

验证方法：
  1. 同时运行 tcpdump: sudo tcpdump -i lo -n -v icmp
  2. 检查输出的包字段是否与我们设定的一致
"""

import socket
import struct
import sys
import os


def calculate_checksum(data: bytes) -> int:
    """
    计算 IP 头部校验和

    算法：
    1. 将头部按 16 位 (2 字节) 分组
    2. 所有 16 位字求和
    3. 将溢出的高 16 位加到低 16 位
    4. 取反码

    这种校验和算法简单高效，可以增量更新（路由器减少 TTL 时不用重算整个头部）
    """
    if len(data) % 2:
        data += b'\x00'  # 奇数长度补零

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    # 将溢出的高位加回
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # 取反码
    return ~checksum & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, payload_len: int,
                    protocol: int = 1, ttl: int = 64) -> bytes:
    """
    手动构建 IPv4 头部

    参数：
        src_ip: 源 IP 地址
        dst_ip: 目的 IP 地址
        payload_len: 载荷长度
        protocol: 上层协议 (1=ICMP, 6=TCP, 17=UDP)
        ttl: 生存时间
    """
    version = 4
    ihl = 5  # 头部长度 = 5 * 4 = 20 bytes (无选项)
    version_ihl = (version << 4) + ihl
    tos = 0  # 服务类型
    total_length = 20 + payload_len  # IP 头 + 载荷
    identification = 54321  # 分片标识
    flags_offset = 0x4000  # DF=1, MF=0, Offset=0 (不允许分片)

    # 先将校验和设为 0，构建头部后再计算
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl,      # 版本 + 头部长度
                         tos,              # 服务类型
                         total_length,     # 总长度
                         identification,   # 标识
                         flags_offset,     # 标志 + 片偏移
                         ttl,             # 生存时间
                         protocol,        # 上层协议
                         0,               # 校验和 (暂时为 0)
                         socket.inet_aton(src_ip),   # 源 IP
                         socket.inet_aton(dst_ip))   # 目的 IP

    # 计算校验和
    checksum = calculate_checksum(header)

    # 重新打包，填入校验和
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_length,
                         identification, flags_offset,
                         ttl, protocol, checksum,
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip))

    return header


def build_icmp_echo(identifier: int = 1, sequence: int = 1,
                    data: bytes = b'') -> bytes:
    """
    构建 ICMP Echo Request

    ICMP 头格式:
    ┌──────────┬──────────┬────────────────────┐
    │ Type (1) │ Code (1) │ Checksum (2)       │
    ├──────────┴──────────┴────────────────────┤
    │ Identifier (2)      │ Sequence (2)       │
    ├─────────────────────┴────────────────────┤
    │ Data (variable)                          │
    └──────────────────────────────────────────┘
    """
    icmp_type = 8  # Echo Request
    icmp_code = 0
    checksum = 0

    # 先构建不含校验和的 ICMP 包
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum,
                              identifier, sequence)
    icmp_packet = icmp_header + data

    # 计算 ICMP 校验和 (覆盖整个 ICMP 包)
    checksum = calculate_checksum(icmp_packet)

    # 重新打包
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum,
                              identifier, sequence)

    return icmp_header + data


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    print("=" * 70)
    print("IP 数据包手动构造演示")
    print("=" * 70)

    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"

    # 构造 ICMP 载荷
    icmp_data = b"Hello from raw IP packet!"
    icmp_packet = build_icmp_echo(identifier=0x1234, sequence=1, data=icmp_data)

    # 构造 IP 头部
    ip_header = build_ip_header(src_ip, dst_ip,
                                payload_len=len(icmp_packet),
                                protocol=1, ttl=64)

    # 完整的 IP 数据包
    packet = ip_header + icmp_packet

    print(f"\n[构造的 IP 包详情]")
    print(f"  源 IP:       {src_ip}")
    print(f"  目的 IP:     {dst_ip}")
    print(f"  TTL:         64")
    print(f"  协议:        ICMP (1)")
    print(f"  IP 头长度:   {len(ip_header)} bytes")
    print(f"  ICMP 长度:   {len(icmp_packet)} bytes")
    print(f"  总长度:      {len(packet)} bytes")

    print(f"\n[IP 头部十六进制]")
    print(f"  {ip_header.hex()}")

    print(f"\n[ICMP 载荷十六进制]")
    print(f"  {icmp_packet.hex()}")

    # 发送原始 IP 包
    # IPPROTO_RAW 表示我们自己构造 IP 头
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        sock.sendto(packet, (dst_ip, 0))
        print(f"\n[✓] 成功发送原始 IP 包到 {dst_ip}")
        print(f"\n验证: sudo tcpdump -i lo -n -v -X icmp")
    except Exception as e:
        print(f"\n[✗] 发送失败: {e}")
    finally:
        sock.close()

    # 校验和验证
    print(f"\n{'=' * 70}")
    print("校验和验证:")
    verify_checksum = calculate_checksum(ip_header)
    print(f"  对完整 IP 头(含校验和)再次计算: 0x{verify_checksum:04x}")
    print(f"  正确时结果应为 0x0000: {'✓ 正确' if verify_checksum == 0 else '✗ 错误'}")
    print("=" * 70)


if __name__ == '__main__':
    main()
