#!/usr/bin/env python3
"""
简易 Traceroute 实现

原理：
  traceroute 利用 IP 头部的 TTL 字段来逐跳发现路由路径。

  工作流程：
  1. 发送 TTL=1 的包 → 第一个路由器收到后 TTL 变为 0
     → 路由器丢弃包并返回 ICMP Time Exceeded (type=11)
  2. 发送 TTL=2 的包 → 第二个路由器返回 Time Exceeded
  3. 依次递增 TTL 直到到达目的地 (收到 ICMP Echo Reply)

  这样就能逐一发现路径上的每个路由器。

运行方式：
  sudo python3 traceroute.py <目标IP或域名>
  sudo python3 traceroute.py 8.8.8.8

验证方法：
  与系统 traceroute 命令对比:
  traceroute -n 8.8.8.8
"""

import socket
import struct
import time
import sys
import os


def calculate_checksum(data: bytes) -> int:
    """计算 ICMP 校验和"""
    if len(data) % 2:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return ~checksum & 0xFFFF


def build_icmp_echo(identifier: int, sequence: int) -> bytes:
    """构建 ICMP Echo Request 包"""
    icmp_type = 8  # Echo Request
    icmp_code = 0
    checksum = 0

    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum,
                         identifier, sequence)
    data = struct.pack('!d', time.time())  # 发送时间戳

    packet = header + data
    checksum = calculate_checksum(packet)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum,
                         identifier, sequence)

    return header + data


def traceroute(dest: str, max_hops: int = 30, timeout: float = 2.0,
               probes_per_hop: int = 3):
    """
    执行 traceroute

    参数：
        dest: 目标地址
        max_hops: 最大跳数
        timeout: 每个探测的超时时间
        probes_per_hop: 每跳发送的探测数
    """
    try:
        dest_ip = socket.gethostbyname(dest)
    except socket.gaierror:
        print(f"错误：无法解析域名 {dest}")
        sys.exit(1)

    print(f"traceroute to {dest} ({dest_ip}), {max_hops} hops max")
    print()

    # 创建原始 ICMP 套接字
    # 发送用 SOCK_RAW + IPPROTO_ICMP
    # 接收也用同一个套接字（可以收到 ICMP 响应）
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(timeout)

    identifier = os.getpid() & 0xFFFF

    for ttl in range(1, max_hops + 1):
        # 设置 TTL
        icmp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        results = []
        hop_addr = None

        for probe in range(probes_per_hop):
            sequence = ttl * 10 + probe
            packet = build_icmp_echo(identifier, sequence)

            send_time = time.time()

            try:
                icmp_sock.sendto(packet, (dest_ip, 0))

                # 等待响应
                while True:
                    recv_data, addr = icmp_sock.recvfrom(1024)
                    recv_time = time.time()

                    # 解析收到的 ICMP 包
                    # IP 头 (至少 20 bytes) + ICMP 头
                    ip_header_len = (recv_data[0] & 0x0F) * 4
                    icmp_header = recv_data[ip_header_len:]
                    icmp_type = icmp_header[0]
                    icmp_code = icmp_header[1]

                    # Type 11: Time Exceeded (路由器返回)
                    # Type 0: Echo Reply (目标返回)
                    if icmp_type == 11 or (icmp_type == 0 and addr[0] == dest_ip):
                        rtt = (recv_time - send_time) * 1000  # ms
                        hop_addr = addr[0]
                        results.append(f"{rtt:.2f} ms")
                        break
                    # 忽略其他 ICMP 消息
                    if time.time() - send_time > timeout:
                        results.append("*")
                        break

            except socket.timeout:
                results.append("*")

        # 输出本跳结果
        if hop_addr:
            try:
                hostname = socket.gethostbyaddr(hop_addr)[0]
                print(f" {ttl:2d}  {hostname} ({hop_addr})  {' '.join(results)}")
            except socket.herror:
                print(f" {ttl:2d}  {hop_addr}  {' '.join(results)}")
        else:
            print(f" {ttl:2d}  * * *")

        # 到达目的地
        if hop_addr == dest_ip:
            print(f"\n到达目标 {dest_ip}")
            break

    icmp_sock.close()


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        print("请使用: sudo python3 traceroute.py <目标>")
        sys.exit(1)

    if len(sys.argv) < 2:
        # 默认 traceroute 到 loopback 作为演示
        dest = "127.0.0.1"
        print("[!] 未指定目标，使用 127.0.0.1 演示")
        print("[!] 实际使用: sudo python3 traceroute.py 8.8.8.8")
        print()
    else:
        dest = sys.argv[1]

    print("=" * 60)
    print("简易 Traceroute")
    print("=" * 60)
    print()
    print("原理: 逐步增加 TTL，收集路径上每个路由器返回的 ICMP Time Exceeded")
    print()

    traceroute(dest)

    print()
    print("验证: 与系统命令对比")
    print(f"  traceroute -n {dest}")


if __name__ == '__main__':
    main()
