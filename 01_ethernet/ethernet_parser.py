#!/usr/bin/env python3
"""
以太网帧解析器 - 使用原始套接字捕获并解析以太网帧

原理：
  通过 AF_PACKET 套接字在 Linux 上直接访问数据链路层，
  捕获经过网卡的原始以太网帧并手动解析各字段。

运行方式：
  sudo python3 ethernet_parser.py

验证方法：
  1. 运行此脚本后，在另一个终端执行 ping 或 curl
  2. 观察输出中解析的 MAC 地址和协议类型
  3. 与 tcpdump 输出对比验证正确性：
     sudo tcpdump -i eth0 -e -c 5
"""

import socket
import struct
import sys


def parse_mac(raw_bytes: bytes) -> str:
    """将 6 字节的 MAC 地址转换为可读格式"""
    return ':'.join(f'{b:02x}' for b in raw_bytes)


def parse_ethertype(etype: int) -> str:
    """解析以太网类型字段"""
    types = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x86DD: 'IPv6',
        0x8100: '802.1Q VLAN',
        0x88CC: 'LLDP',
    }
    return types.get(etype, f'Unknown(0x{etype:04x})')


def parse_ethernet_frame(data: bytes) -> dict:
    """
    解析以太网帧头部 (14 字节)

    帧结构：
    ┌─────────────┬─────────────┬───────────┬──────────┐
    │ Dst MAC (6) │ Src MAC (6) │ Type (2)  │ Payload  │
    └─────────────┴─────────────┴───────────┴──────────┘
    """
    if len(data) < 14:
        raise ValueError(f"数据太短，无法解析以太网帧: {len(data)} bytes")

    dst_mac = parse_mac(data[0:6])
    src_mac = parse_mac(data[6:12])
    ethertype = struct.unpack('!H', data[12:14])[0]

    return {
        'dst_mac': dst_mac,
        'src_mac': src_mac,
        'ethertype': ethertype,
        'ethertype_name': parse_ethertype(ethertype),
        'payload': data[14:],
    }


def parse_ipv4_header(data: bytes) -> dict:
    """解析 IPv4 头部的关键字段"""
    if len(data) < 20:
        return {}

    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    total_length = struct.unpack('!H', data[2:4])[0]
    ttl = data[8]
    protocol = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    proto_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

    return {
        'version': version,
        'header_length': ihl,
        'total_length': total_length,
        'ttl': ttl,
        'protocol': proto_names.get(protocol, str(protocol)),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
    }


def main():
    # 创建原始套接字，监听所有以太网帧
    # AF_PACKET: 数据链路层访问
    # SOCK_RAW: 原始帧（包含链路层头部）
    # ETH_P_ALL (0x0003): 接收所有协议类型的帧
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("错误：需要 root 权限运行此脚本")
        print("请使用: sudo python3 ethernet_parser.py")
        sys.exit(1)

    print("=" * 70)
    print("以太网帧解析器 - 按 Ctrl+C 停止")
    print("=" * 70)
    print()

    frame_count = 0
    max_frames = 20  # 捕获 20 帧后自动停止

    try:
        while frame_count < max_frames:
            # 接收原始帧数据
            data, addr = sock.recvfrom(65535)
            frame_count += 1

            # 解析以太网帧
            frame = parse_ethernet_frame(data)

            print(f"[帧 #{frame_count}] 长度={len(data)} bytes")
            print(f"  源 MAC:    {frame['src_mac']}")
            print(f"  目的 MAC:  {frame['dst_mac']}")
            print(f"  类型:      {frame['ethertype_name']} (0x{frame['ethertype']:04x})")

            # 如果是 IPv4，继续解析 IP 头
            if frame['ethertype'] == 0x0800:
                ip_info = parse_ipv4_header(frame['payload'])
                if ip_info:
                    print(f"  IPv4: {ip_info['src_ip']} -> {ip_info['dst_ip']}")
                    print(f"         协议={ip_info['protocol']} TTL={ip_info['ttl']}")

            print()

    except KeyboardInterrupt:
        print(f"\n捕获结束，共解析 {frame_count} 帧")
    finally:
        sock.close()


if __name__ == '__main__':
    main()
