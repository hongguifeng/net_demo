#!/usr/bin/env python3
"""
TUN ICMP Echo 响应器 - 在用户态实现 ping 回复

原理：
  当 ping 10.0.0.2 时，ICMP Echo Request 包被路由到 TUN 设备。
  我们的程序从 TUN 读取这个包，构造 ICMP Echo Reply，写回 TUN。
  内核收到 Reply 后转发给 ping 进程。

  这是用户态网络协议栈的最简单示例：
  - 从 TUN 读取 IP 包
  - 在用户态处理（构造回复）
  - 将回复写回 TUN

  流程：
  ping 10.0.0.2  →  内核路由  →  TUN fd (读)
       ↑                              |
       |                              v
  内核路由   ←  TUN fd (写)  ←  用户态处理
                                (交换 src/dst, 修改 type)

运行方式：
  # 终端1: 启动响应器
  sudo python3 tun_echo.py

  # 终端2: ping
  ping -c 5 10.0.0.2

验证方法：
  ping 应该能收到回复（说明我们的用户态协议栈正确处理了 ICMP）
"""

import os
import sys
import struct
import fcntl
import subprocess
import socket

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def create_tun(name: str = 'tun0') -> int:
    """创建 TUN 设备"""
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd


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


def make_icmp_reply(icmp_data: bytes) -> bytes:
    """
    将 ICMP Echo Request 转换为 Echo Reply

    只需要:
    1. 将 Type 从 8 (Request) 改为 0 (Reply)
    2. 重新计算 ICMP 校验和
    其他字段 (Identifier, Sequence, Data) 保持不变
    """
    # 修改类型为 0 (Echo Reply)，保留其他字段
    reply = bytes([0, 0]) + b'\x00\x00' + icmp_data[4:]

    # 重新计算校验和
    checksum = calculate_checksum(reply)
    reply = bytes([0, 0]) + struct.pack('!H', checksum) + icmp_data[4:]

    return reply


def make_ip_reply(original_packet: bytes, new_payload: bytes) -> bytes:
    """
    构造 IP 回复包

    交换源/目的地址，更新长度和校验和
    """
    ihl = (original_packet[0] & 0x0F) * 4
    total_length = ihl + len(new_payload)

    # 复制原始头部
    reply_header = bytearray(original_packet[:ihl])

    # 交换源/目的 IP
    reply_header[12:16] = original_packet[16:20]  # 新的源 = 原来的目的
    reply_header[16:20] = original_packet[12:16]  # 新的目的 = 原来的源

    # 更新总长度
    struct.pack_into('!H', reply_header, 2, total_length)

    # 清零校验和后重新计算
    reply_header[10:12] = b'\x00\x00'
    checksum = calculate_checksum(bytes(reply_header))
    struct.pack_into('!H', reply_header, 10, checksum)

    return bytes(reply_header) + new_payload


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    tun_name = 'tun0'
    tun_ip = '10.0.0.1'
    peer_ip = '10.0.0.2'

    print("=" * 60)
    print("TUN ICMP Echo 响应器 (用户态 ping 服务)")
    print("=" * 60)
    print()

    # 创建 TUN
    tun_fd = create_tun(tun_name)
    print(f"[✓] 创建 TUN 设备: {tun_name}")

    # 配置 IP
    subprocess.run(['ip', 'addr', 'add', f'{tun_ip}/24', 'dev', tun_name],
                   check=True, capture_output=True)
    subprocess.run(['ip', 'link', 'set', tun_name, 'up'],
                   check=True, capture_output=True)
    print(f"[✓] 配置 IP: {tun_ip}/24")
    print(f"[✓] 模拟对端: {peer_ip}")
    print()
    print(f"[*] 等待 ICMP 请求... (在另一终端执行: ping -c 5 {peer_ip})")
    print(f"[*] 按 Ctrl+C 停止")
    print()

    reply_count = 0
    try:
        while True:
            # 从 TUN 读取 IP 包
            packet = os.read(tun_fd, 4096)

            if len(packet) < 20:
                continue

            # 解析 IP 头
            version = packet[0] >> 4
            ihl = (packet[0] & 0x0F) * 4
            protocol = packet[9]
            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])

            # 只处理 ICMP
            if protocol != 1:
                print(f"  [跳过] 非 ICMP 包: proto={protocol} {src_ip}→{dst_ip}")
                continue

            # 解析 ICMP
            icmp_data = packet[ihl:]
            if len(icmp_data) < 8:
                continue

            icmp_type = icmp_data[0]
            icmp_code = icmp_data[1]
            icmp_id = struct.unpack('!H', icmp_data[4:6])[0]
            icmp_seq = struct.unpack('!H', icmp_data[6:8])[0]

            if icmp_type == 8:  # Echo Request
                print(f"  [请求] {src_ip} → {dst_ip} "
                      f"id=0x{icmp_id:04x} seq={icmp_seq}")

                # 构造 ICMP Reply
                icmp_reply = make_icmp_reply(icmp_data)

                # 构造 IP Reply (交换源目的)
                ip_reply = make_ip_reply(packet, icmp_reply)

                # 写回 TUN
                os.write(tun_fd, ip_reply)
                reply_count += 1
                print(f"  [回复] {dst_ip} → {src_ip} "
                      f"id=0x{icmp_id:04x} seq={icmp_seq} ✓")

    except KeyboardInterrupt:
        print(f"\n\n停止. 共回复 {reply_count} 个 ICMP Echo Request")
    finally:
        os.close(tun_fd)
        print("[✓] TUN 设备已关闭")


if __name__ == '__main__':
    main()
