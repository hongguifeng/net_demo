#!/usr/bin/env python3
"""
TAP 设备桥接演示

原理：
  TAP 设备工作在 L2 (数据链路层)，处理的是以太网帧而非 IP 包。
  这使得 TAP 适合模拟完整的以太网连接。

  TAP vs TUN:
  - TAP 读/写以太网帧 (包含 MAC 头)
  - TUN 读/写 IP 包 (无 MAC 头)

  TAP 的典型用途：
  - 虚拟机网络 (QEMU/KVM 使用 TAP 连接 VM 到宿主网络)
  - 容器网络桥接
  - 协议测试

  本示例创建 TAP 设备，配置 IP，并响应 ARP 和 ICMP。

运行方式：
  sudo python3 tap_bridge.py

验证方法：
  # 终端2:
  ping -c 3 10.1.0.2
  arp -n | grep 10.1.0
"""

import os
import sys
import struct
import fcntl
import subprocess
import socket

TUNSETIFF = 0x400454ca
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


def create_tap(name: str = 'tap0') -> int:
    """创建 TAP 设备"""
    tap_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(tap_fd, TUNSETIFF, ifr)
    return tap_fd


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


def parse_ethernet(frame: bytes) -> dict:
    """解析以太网帧"""
    if len(frame) < 14:
        return {}
    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    ethertype = struct.unpack('!H', frame[12:14])[0]
    return {
        'dst_mac': dst_mac,
        'src_mac': src_mac,
        'ethertype': ethertype,
        'payload': frame[14:],
    }


def mac_to_str(mac: bytes) -> str:
    """MAC 地址转字符串"""
    return ':'.join(f'{b:02x}' for b in mac)


def build_arp_reply(request_frame: bytes, our_mac: bytes, our_ip: str) -> bytes:
    """
    构造 ARP 回复帧

    ARP 请求格式:
    以太网头(14B) + ARP数据(28B)

    ARP 数据:
    HW Type(2) + Proto Type(2) + HW Len(1) + Proto Len(1) +
    Opcode(2) + Sender MAC(6) + Sender IP(4) + Target MAC(6) + Target IP(4)
    """
    eth = parse_ethernet(request_frame)
    arp_data = eth['payload']

    if len(arp_data) < 28:
        return b''

    # 解析请求方信息
    sender_mac = arp_data[8:14]
    sender_ip = arp_data[14:18]
    target_ip = arp_data[24:28]

    # 构造 ARP Reply
    # 以太网头：目的=请求方MAC，源=我们的MAC，类型=ARP(0x0806)
    eth_header = sender_mac + our_mac + struct.pack('!H', 0x0806)

    # ARP Reply
    arp_reply = struct.pack('!HHBBH',
                            1,      # HW Type: Ethernet
                            0x0800, # Protocol: IPv4
                            6,      # HW Len
                            4,      # Proto Len
                            2)      # Opcode: Reply
    arp_reply += our_mac                    # Sender MAC (我们)
    arp_reply += socket.inet_aton(our_ip)   # Sender IP (我们)
    arp_reply += sender_mac                 # Target MAC (请求方)
    arp_reply += sender_ip                  # Target IP (请求方)

    return eth_header + arp_reply


def build_icmp_reply_frame(request_frame: bytes, our_mac: bytes) -> bytes:
    """
    构造 ICMP Echo Reply 以太网帧

    需要处理 3 层:
    1. 以太网头 (交换 MAC)
    2. IP 头 (交换 IP)
    3. ICMP (修改 type 为 0)
    """
    eth = parse_ethernet(request_frame)
    ip_data = eth['payload']

    if len(ip_data) < 20:
        return b''

    ihl = (ip_data[0] & 0x0F) * 4
    protocol = ip_data[9]

    if protocol != 1:  # 非 ICMP
        return b''

    icmp_data = ip_data[ihl:]
    if len(icmp_data) < 8 or icmp_data[0] != 8:  # 非 Echo Request
        return b''

    # 1. 以太网头：交换 MAC
    new_eth = eth['src_mac'] + our_mac + struct.pack('!H', 0x0800)

    # 2. IP 头：交换源目的 IP
    new_ip = bytearray(ip_data[:ihl])
    new_ip[12:16] = ip_data[16:20]  # src = 原 dst
    new_ip[16:20] = ip_data[12:16]  # dst = 原 src
    new_ip[10:12] = b'\x00\x00'     # 清零校验和
    checksum = calculate_checksum(bytes(new_ip))
    struct.pack_into('!H', new_ip, 10, checksum)

    # 3. ICMP: type=0 (Reply), 重算校验和
    new_icmp = bytearray(icmp_data)
    new_icmp[0] = 0  # Type = Echo Reply
    new_icmp[2:4] = b'\x00\x00'  # 清零校验和
    checksum = calculate_checksum(bytes(new_icmp))
    struct.pack_into('!H', new_icmp, 2, checksum)

    return new_eth + bytes(new_ip) + bytes(new_icmp)


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    tap_name = 'tap0'
    tap_ip = '10.1.0.1'
    virtual_ip = '10.1.0.2'  # 我们在用户态模拟的设备 IP
    virtual_mac = b'\x02\x00\x00\x00\x00\x02'  # 虚拟 MAC

    print("=" * 60)
    print("TAP 设备桥接演示")
    print("=" * 60)
    print()

    # 创建 TAP
    tap_fd = create_tap(tap_name)
    print(f"[✓] 创建 TAP 设备: {tap_name}")

    # 配置 TAP (内核侧的 IP)
    subprocess.run(['ip', 'addr', 'add', f'{tap_ip}/24', 'dev', tap_name],
                   check=True, capture_output=True)
    subprocess.run(['ip', 'link', 'set', tap_name, 'up'],
                   check=True, capture_output=True)
    print(f"[✓] TAP IP: {tap_ip}/24")
    print(f"[✓] 虚拟设备 IP: {virtual_ip} MAC: {mac_to_str(virtual_mac)}")
    print()
    print(f"[*] 在另一终端执行: ping -c 3 {virtual_ip}")
    print(f"[*] TAP 处理以太网帧 (含 ARP + ICMP)")
    print(f"[*] 按 Ctrl+C 停止")
    print()

    frame_count = 0
    try:
        while True:
            frame = os.read(tap_fd, 4096)
            frame_count += 1

            eth = parse_ethernet(frame)
            if not eth:
                continue

            dst_str = mac_to_str(eth['dst_mac'])
            src_str = mac_to_str(eth['src_mac'])

            if eth['ethertype'] == 0x0806:  # ARP
                arp_data = eth['payload']
                if len(arp_data) >= 28:
                    opcode = struct.unpack('!H', arp_data[6:8])[0]
                    target_ip_bytes = arp_data[24:28]
                    target_ip_str = socket.inet_ntoa(target_ip_bytes)

                    if opcode == 1 and target_ip_str == virtual_ip:
                        # ARP Request for our virtual IP
                        print(f"  [ARP Request] Who has {virtual_ip}? Tell {src_str}")
                        reply = build_arp_reply(frame, virtual_mac, virtual_ip)
                        if reply:
                            os.write(tap_fd, reply)
                            print(f"  [ARP Reply]   {virtual_ip} is at "
                                  f"{mac_to_str(virtual_mac)} ✓")

            elif eth['ethertype'] == 0x0800:  # IPv4
                ip_data = eth['payload']
                if len(ip_data) >= 20:
                    src_ip = socket.inet_ntoa(ip_data[12:16])
                    dst_ip = socket.inet_ntoa(ip_data[16:20])
                    protocol = ip_data[9]

                    if protocol == 1 and dst_ip == virtual_ip:
                        # ICMP to our virtual IP
                        ihl = (ip_data[0] & 0x0F) * 4
                        icmp = ip_data[ihl:]
                        if icmp and icmp[0] == 8:
                            seq = struct.unpack('!H', icmp[6:8])[0]
                            print(f"  [ICMP Request] {src_ip} → {dst_ip} seq={seq}")
                            reply = build_icmp_reply_frame(frame, virtual_mac)
                            if reply:
                                os.write(tap_fd, reply)
                                print(f"  [ICMP Reply]   {dst_ip} → {src_ip} seq={seq} ✓")

    except KeyboardInterrupt:
        print(f"\n\n停止. 共处理 {frame_count} 帧")
    finally:
        os.close(tap_fd)
        print("[✓] TAP 设备已关闭")


if __name__ == '__main__':
    main()
