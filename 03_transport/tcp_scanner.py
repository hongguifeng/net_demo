#!/usr/bin/env python3
"""
TCP SYN 端口扫描器

原理：
  SYN 扫描 (半开放扫描) 是最常用的端口扫描技术。

  工作流程：
  1. 发送 SYN 包到目标端口
  2. 如果收到 SYN+ACK → 端口开放
  3. 如果收到 RST → 端口关闭
  4. 如果超时无响应 → 端口被过滤 (防火墙丢弃)

  优点：
  - 比完整三次握手快（不需要第三步 ACK）
  - 不会在目标留下完整连接日志（因为连接未真正建立）

运行方式：
  sudo python3 tcp_scanner.py <目标IP> [起始端口] [结束端口]
  sudo python3 tcp_scanner.py 127.0.0.1 1 1024

验证方法：
  1. 先在本地开几个端口: python3 -m http.server 8080 &
  2. 用 nmap 对比: nmap -sS -p1-1024 127.0.0.1
"""

import socket
import struct
import sys
import os
import time
import select
import random


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


def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """构建 TCP SYN 包"""
    seq = random.randint(0, 0xFFFFFFFF)
    data_offset = 5
    flags = 0x02  # SYN
    window = 1024

    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, 0,
                             (data_offset << 4), flags, window, 0, 0)

    # 伪头部
    pseudo_header = struct.pack('!4s4sBBH',
                                socket.inet_aton(src_ip),
                                socket.inet_aton(dst_ip),
                                0, 6, len(tcp_header))

    checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, 0,
                             (data_offset << 4), flags, window, checksum, 0)

    return tcp_header


def syn_scan(target_ip: str, ports: list, timeout: float = 1.0) -> dict:
    """
    执行 SYN 扫描

    返回: {port: status} status 可以是 'open', 'closed', 'filtered'
    """
    results = {}
    src_ip = "127.0.0.1"

    # 创建原始 TCP 套接字
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock.setblocking(False)

    # 使用随机源端口范围
    base_src_port = random.randint(40000, 50000)

    # 发送 SYN 到所有目标端口
    port_map = {}  # src_port -> dst_port 映射
    for i, port in enumerate(ports):
        src_port = base_src_port + i
        port_map[src_port] = port

        syn = build_syn_packet(src_ip, target_ip, src_port, port)
        try:
            send_sock.sendto(syn, (target_ip, 0))
        except Exception:
            pass

        # 避免发送过快
        if i % 100 == 0 and i > 0:
            time.sleep(0.01)

    # 等待响应
    start_time = time.time()
    responded_ports = set()

    while time.time() - start_time < timeout:
        readable, _, _ = select.select([recv_sock], [], [], 0.1)
        if not readable:
            continue

        try:
            data, addr = recv_sock.recvfrom(65535)
        except BlockingIOError:
            continue

        if addr[0] != target_ip:
            continue

        # 解析 IP 头
        ip_header_len = (data[0] & 0x0F) * 4
        tcp_data = data[ip_header_len:]

        if len(tcp_data) < 14:
            continue

        tcp_src_port = struct.unpack('!H', tcp_data[0:2])[0]
        tcp_dst_port = struct.unpack('!H', tcp_data[2:4])[0]
        tcp_flags = tcp_data[13]

        # 检查是否是我们发出的探测的响应
        if tcp_dst_port in port_map:
            dst_port = port_map[tcp_dst_port]
            responded_ports.add(dst_port)

            if tcp_flags & 0x12 == 0x12:  # SYN+ACK
                results[dst_port] = 'open'
            elif tcp_flags & 0x04:  # RST
                results[dst_port] = 'closed'

    # 没有响应的端口标记为 filtered
    for port in ports:
        if port not in results:
            results[port] = 'filtered'

    send_sock.close()
    recv_sock.close()

    return results


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 100

    print("=" * 60)
    print("TCP SYN 端口扫描器")
    print("=" * 60)
    print(f"\n  目标:     {target_ip}")
    print(f"  端口范围: {start_port}-{end_port}")
    print(f"  扫描方式: SYN (半开放)")
    print()

    ports = list(range(start_port, end_port + 1))
    start_time = time.time()

    results = syn_scan(target_ip, ports)

    elapsed = time.time() - start_time

    # 输出结果
    open_ports = {p: s for p, s in sorted(results.items()) if s == 'open'}
    closed_count = sum(1 for s in results.values() if s == 'closed')
    filtered_count = sum(1 for s in results.values() if s == 'filtered')

    if open_ports:
        print(f"  {'端口':<10} {'状态':<12} {'服务':<20}")
        print(f"  {'-'*42}")
        common_services = {
            22: 'ssh', 25: 'smtp', 53: 'dns', 80: 'http',
            443: 'https', 3306: 'mysql', 5432: 'postgresql',
            6379: 'redis', 8080: 'http-alt', 9999: 'test'
        }
        for port, status in open_ports.items():
            service = common_services.get(port, 'unknown')
            print(f"  {port:<10} {status:<12} {service:<20}")
    else:
        print("  未发现开放端口")

    print(f"\n  扫描统计:")
    print(f"    开放:   {len(open_ports)}")
    print(f"    关闭:   {closed_count}")
    print(f"    过滤:   {filtered_count}")
    print(f"    耗时:   {elapsed:.2f}s")

    print(f"\n  验证: nmap -sS -p{start_port}-{end_port} {target_ip}")


if __name__ == '__main__':
    main()
