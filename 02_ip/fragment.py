#!/usr/bin/env python3
"""
IP 分片与重组演示

原理：
  当 IP 数据包大小超过链路层的 MTU (Maximum Transmission Unit) 时，
  需要将数据包分片 (fragmentation) 传输，目的主机负责重组 (reassembly)。

  分片相关字段：
  - Identification: 同一数据包的所有分片共享相同的标识
  - Flags:
    - DF (Don't Fragment): 设置时禁止分片
    - MF (More Fragments): 设置时表示后面还有更多分片
  - Fragment Offset: 分片数据在原始数据中的偏移 (以 8 字节为单位)

  分片示意:
  原始包 (3000 bytes payload, MTU=1500):
  ┌────────────────────────────────────────────────────────┐
  │           Original IP Packet (3020 bytes)              │
  └────────────────────────────────────────────────────────┘
                           ↓ 分片
  ┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────┐
  │ Fragment 1 (1500 bytes)  │  │ Fragment 2 (1500 bytes)  │  │ Frag 3   │
  │ Offset=0, MF=1          │  │ Offset=185, MF=1         │  │ Off=370  │
  └──────────────────────────┘  └──────────────────────────┘  └──────────┘

运行方式：
  sudo python3 fragment.py

验证方法：
  sudo tcpdump -i lo -n -v 'ip[6:2] & 0x3fff != 0 or ip[6] & 0x20 != 0'
  (捕获分片包: MF=1 或 offset!=0)
"""

import socket
import struct
import sys
import os


def calculate_checksum(data: bytes) -> int:
    """计算校验和"""
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, total_length: int,
                    identification: int, flags: int, offset: int,
                    protocol: int = 1, ttl: int = 64) -> bytes:
    """
    构建 IP 头部，支持分片标志设置

    参数：
        flags: 3 bits (0, DF, MF)
        offset: 分片偏移 (以 8 字节为单位)
    """
    version_ihl = (4 << 4) + 5
    tos = 0
    flags_offset = (flags << 13) | offset

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


def fragment_payload(payload: bytes, mtu: int = 1500) -> list:
    """
    将载荷分片

    参数：
        payload: 原始载荷数据
        mtu: 最大传输单元

    返回：
        分片列表 [(offset, more_fragments, fragment_data), ...]

    注意：
        - 每个分片的 IP 头为 20 字节
        - 分片载荷最大为 MTU - 20
        - Fragment Offset 字段以 8 字节为单位，所以每片数据长度必须是 8 的倍数
    """
    max_fragment_data = mtu - 20  # 减去 IP 头
    # 确保是 8 的倍数
    max_fragment_data = (max_fragment_data // 8) * 8

    fragments = []
    offset = 0

    while offset < len(payload):
        end = offset + max_fragment_data
        if end >= len(payload):
            # 最后一片
            fragment_data = payload[offset:]
            more_fragments = False
        else:
            fragment_data = payload[offset:end]
            more_fragments = True

        fragments.append((offset // 8, more_fragments, fragment_data))
        offset = end

    return fragments


def reassemble_fragments(fragments: list) -> bytes:
    """
    重组分片

    参数：
        fragments: [(offset_in_8bytes, more_fragments, data), ...]

    返回：
        重组后的完整载荷
    """
    # 按偏移排序
    sorted_frags = sorted(fragments, key=lambda x: x[0])

    # 验证完整性
    expected_offset = 0
    for offset, mf, data in sorted_frags:
        if offset != expected_offset:
            raise ValueError(f"分片不连续: 期望偏移 {expected_offset}, 实际 {offset}")
        expected_offset = offset + len(data) // 8

    # 验证最后一片 MF=0
    if sorted_frags[-1][1]:
        raise ValueError("缺少最后一个分片 (最后一片应该 MF=0)")

    # 重组
    return b''.join(data for _, _, data in sorted_frags)


def demo_fragmentation():
    """演示 IP 分片过程"""
    print("=" * 70)
    print("IP 分片演示")
    print("=" * 70)

    # 构造一个大载荷 (3000 bytes)
    original_payload = bytes(range(256)) * 12  # 3072 bytes
    original_payload = original_payload[:3000]

    mtu = 1500
    print(f"\n[原始数据]")
    print(f"  载荷大小: {len(original_payload)} bytes")
    print(f"  MTU:      {mtu} bytes")
    print(f"  需要分片: {'是' if len(original_payload) + 20 > mtu else '否'}")

    # 执行分片
    fragments = fragment_payload(original_payload, mtu)

    print(f"\n[分片结果] 共 {len(fragments)} 片")
    print(f"  {'序号':<6} {'偏移(8B)':<10} {'偏移(B)':<10} {'长度':<8} {'MF':<4}")
    print(f"  {'-'*40}")
    for i, (offset, mf, data) in enumerate(fragments):
        print(f"  {i+1:<6} {offset:<10} {offset*8:<10} {len(data):<8} {int(mf):<4}")

    # 重组
    print(f"\n[重组验证]")
    reassembled = reassemble_fragments(fragments)
    is_correct = reassembled == original_payload
    print(f"  重组后大小: {len(reassembled)} bytes")
    print(f"  数据一致:   {'✓ 正确' if is_correct else '✗ 错误'}")

    return fragments


def demo_send_fragments():
    """实际发送分片包"""
    print(f"\n{'=' * 70}")
    print("发送分片包到 loopback")
    print("=" * 70)

    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"
    identification = 12345

    # 创建 ICMP Echo Request 的载荷 (较大)
    icmp_type = 8
    icmp_code = 0
    icmp_id = 0x5678
    icmp_seq = 1

    # ICMP 头 + 大载荷
    icmp_data = b'A' * 2000
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
    icmp_packet = icmp_header + icmp_data
    # 计算 ICMP 校验和
    checksum = calculate_checksum(icmp_packet)
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
    icmp_packet = icmp_header + icmp_data

    # 手动分片
    mtu = 1500
    fragments = fragment_payload(icmp_packet, mtu)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f"\n  原始 ICMP 包大小: {len(icmp_packet)} bytes")
    print(f"  分片数: {len(fragments)}")
    print()

    for i, (offset, mf, data) in enumerate(fragments):
        # flags: bit 1 = DF, bit 0 = MF
        flags = 0b001 if mf else 0b000  # MF flag

        ip_header = build_ip_header(
            src_ip, dst_ip,
            total_length=20 + len(data),
            identification=identification,
            flags=flags,
            offset=offset,
            protocol=1,  # ICMP
            ttl=64
        )

        packet = ip_header + data
        sock.sendto(packet, (dst_ip, 0))
        print(f"  [发送] 分片 {i+1}: offset={offset*8}, len={len(data)}, MF={int(mf)}")

    sock.close()
    print(f"\n  [✓] 所有分片发送完成")
    print(f"\n  验证命令:")
    print(f"  sudo tcpdump -i lo -n -v 'ip[6:2] & 0x3fff != 0 or ip[6] & 0x20 != 0'")


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    demo_fragmentation()
    demo_send_fragments()

    print(f"\n{'=' * 70}")
    print("总结:")
    print("  - IP 分片发生在数据包超过链路 MTU 时")
    print("  - 分片通过 Identification 字段关联，通过 Offset 字段定位")
    print("  - MF=1 表示后面还有分片，MF=0 表示最后一片")
    print("  - Fragment Offset 以 8 字节为单位")
    print("  - 目的主机负责重组，中间路由器不负责重组")
    print("  - 现代网络倾向使用 Path MTU Discovery 避免分片")
    print("=" * 70)


if __name__ == '__main__':
    main()
