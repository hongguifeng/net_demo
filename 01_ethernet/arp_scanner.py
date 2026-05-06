#!/usr/bin/env python3
"""
ARP 扫描器 - 扫描局域网内活动主机

原理：
  ARP (Address Resolution Protocol) 用于将 IP 地址映射到 MAC 地址。
  发送 ARP 请求广播包，收集响应来发现同一广播域内的活动主机。

  ARP 请求格式:
  ┌──────────────┬──────────────┬──────────┬──────────────┬──────────────┐
  │ HW Type (2B) │ Proto (2B)   │ Len (2B) │ Opcode (2B)  │              │
  ├──────────────┴──────────────┴──────────┴──────────────┘              │
  │ Sender MAC (6B) │ Sender IP (4B) │ Target MAC (6B) │ Target IP (4B) │
  └────────────────────────────────────────────────────────────────────────┘

  Opcode:
    1 = ARP Request (who-has)
    2 = ARP Reply (is-at)

运行方式：
  sudo python3 arp_scanner.py [网段]
  sudo python3 arp_scanner.py 192.168.1.0/24

验证方法：
  1. 对比 arp -n 命令的输出
  2. 使用 nmap -sn 192.168.1.0/24 对比结果
"""

from scapy.all import Ether, ARP, srp, conf
import sys
import os
import ipaddress


def arp_scan(network: str, timeout: int = 2) -> list:
    """
    对指定网段执行 ARP 扫描

    参数：
        network: CIDR 格式的网段，如 "192.168.1.0/24"
        timeout: 等待响应的超时时间（秒）

    返回：
        活动主机列表 [(ip, mac), ...]
    """
    # 构造 ARP 请求包
    # Ether(dst="ff:ff:ff:ff:ff:ff") - 广播帧
    # ARP(pdst=network) - 目标网段的 ARP who-has 请求
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    print(f"[*] 扫描网段: {network}")
    print(f"[*] 发送 ARP 广播请求...")
    print(f"[*] 超时设置: {timeout}s")
    print()

    # srp() - 发送并接收二层数据包
    # 返回 (已回复列表, 未回复列表)
    answered, unanswered = srp(arp_request, timeout=timeout, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
        })

    return hosts


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限运行此脚本")
        print("请使用: sudo python3 arp_scanner.py [网段]")
        sys.exit(1)

    # 确定扫描网段
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        # 默认扫描 loopback 网段作为演示
        network = "127.0.0.1/32"
        print("[!] 未指定网段，使用 127.0.0.1/32 作为演示")
        print("[!] 实际使用时请指定网段: sudo python3 arp_scanner.py 192.168.1.0/24")
        print()

    # 验证网段格式
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"错误：无效的网段格式: {e}")
        sys.exit(1)

    conf.verb = 0

    print("=" * 60)
    print("ARP 局域网扫描器")
    print("=" * 60)
    print()

    hosts = arp_scan(network)

    if hosts:
        print(f"[+] 发现 {len(hosts)} 台活动主机:")
        print()
        print(f"{'IP 地址':<18} {'MAC 地址':<20}")
        print("-" * 40)
        for host in sorted(hosts, key=lambda x: ipaddress.ip_address(x['ip'])):
            print(f"{host['ip']:<18} {host['mac']:<20}")
    else:
        print("[-] 未发现活动主机")
        print("    (如果扫描 loopback，这是正常的 - loopback 不使用 ARP)")

    print()
    print("=" * 60)
    print("验证方法:")
    print("  1. arp -n              # 查看系统 ARP 缓存")
    print("  2. ip neigh show       # 查看邻居表")
    print("  3. nmap -sn <network>  # 使用 nmap 对比")
    print("=" * 60)


if __name__ == '__main__':
    main()
