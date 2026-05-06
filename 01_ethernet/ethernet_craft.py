#!/usr/bin/env python3
"""
以太网帧构造 - 使用 scapy 构造并发送自定义以太网帧

原理：
  scapy 允许我们逐层构造网络包，从以太网帧到 IP 层，
  完全控制每个字段的值。这对于理解协议格式和网络测试非常有用。

运行方式：
  sudo python3 ethernet_craft.py

验证方法：
  1. 在另一个终端运行 tcpdump 捕获验证：
     sudo tcpdump -i lo -e -n -c 5 icmp
  2. 观察 scapy 构造的包与手动设定的字段是否一致
"""

from scapy.all import Ether, IP, ICMP, Raw, sendp, hexdump, conf
import sys
import os


def demo_frame_structure():
    """演示以太网帧的各层结构"""
    print("=" * 70)
    print("演示 1: 以太网帧结构分析")
    print("=" * 70)

    # 构造一个完整的以太网帧
    frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01", type=0x0800)
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
        / ICMP(type=8, code=0)  # Echo Request
        / Raw(load=b"Hello from ethernet_craft!")
    )

    print("\n[分层视图]")
    frame.show()

    print("\n[十六进制转储]")
    hexdump(frame)

    print(f"\n[帧总长度] {len(frame)} bytes")
    print(f"  以太网头: 14 bytes")
    print(f"  IP 头:    20 bytes")
    print(f"  ICMP 头:  8 bytes")
    print(f"  数据:     {len(b'Hello from ethernet_craft!')} bytes")

    return frame


def demo_send_frame():
    """通过 loopback 发送自定义帧"""
    print("\n" + "=" * 70)
    print("演示 2: 发送自定义以太网帧 (loopback)")
    print("=" * 70)

    # 使用 loopback 接口避免影响真实网络
    frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / ICMP()
        / Raw(load=b"Test packet")
    )

    print(f"\n发送帧到 loopback 接口...")
    sendp(frame, iface="lo", verbose=True)
    print("发送完成！")
    print("\n验证: 请在另一终端运行 'sudo tcpdump -i lo -e icmp' 查看")


def demo_vlan_frame():
    """演示 802.1Q VLAN 标记帧"""
    print("\n" + "=" * 70)
    print("演示 3: 802.1Q VLAN 帧结构")
    print("=" * 70)

    from scapy.all import Dot1Q

    # 带 VLAN 标签的帧
    vlan_frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01")
        / Dot1Q(vlan=100, prio=5)  # VLAN ID=100, 优先级=5
        / IP(src="192.168.100.1", dst="192.168.100.2")
        / ICMP()
    )

    print("\n[VLAN 帧分层视图]")
    vlan_frame.show()

    print(f"\n[VLAN 帧长度] {len(vlan_frame)} bytes")
    print(f"  注意: 比普通帧多 4 bytes (802.1Q tag)")
    print(f"  VLAN ID: 100")
    print(f"  优先级:  5 (范围 0-7)")


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限运行此脚本")
        print("请使用: sudo python3 ethernet_craft.py")
        sys.exit(1)

    # 关闭 scapy 的冗余输出
    conf.verb = 0

    demo_frame_structure()
    demo_send_frame()
    demo_vlan_frame()

    print("\n" + "=" * 70)
    print("总结:")
    print("  - 以太网帧是 L2 的基本单位，头部固定 14 bytes")
    print("  - 帧类型字段决定了上层协议 (IPv4=0x0800)")
    print("  - 802.1Q 在帧中插入 4 bytes 的 VLAN 标签")
    print("  - MTU 限制了单帧的最大有效载荷为 1500 bytes")
    print("=" * 70)


if __name__ == '__main__':
    main()
