#!/usr/bin/env python3
"""
TUN 设备创建与基本操作

原理：
  TUN 设备是一个虚拟的三层网络接口。用户态程序通过文件描述符
  读写 IP 数据包，内核则像处理真实网卡一样路由这些包。

  创建流程：
  1. 打开 /dev/net/tun
  2. 通过 ioctl(TUNSETIFF) 配置设备类型和名称
  3. 用 ip 命令配置 IP 地址并启动接口
  4. read()/write() 操作 IP 包

  文件描述符的数据格式 (TUN):
  ┌───────────────────────────────────────────┐
  │ [Flags 4B (可选)] │ IP Packet            │
  └───────────────────────────────────────────┘
  如果设置了 IFF_NO_PI，则没有 4 字节的前缀信息。

运行方式：
  sudo python3 tun_device.py

验证方法：
  # 终端2: 查看 TUN 设备
  ip addr show tun0
  ip route show dev tun0

  # 终端3: ping TUN 设备
  ping -c 3 10.0.0.1
"""

import os
import sys
import struct
import fcntl
import subprocess
import socket
import time

# Linux TUN/TAP ioctl 常量
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000  # 不包含协议信息前缀


def create_tun(name: str = 'tun0') -> int:
    """
    创建 TUN 设备

    返回: 文件描述符

    步骤：
    1. 打开 /dev/net/tun 字符设备
    2. 用 ioctl 设置设备名称和类型
    3. 返回的 fd 就是 TUN 设备的数据通道
    """
    # 打开 TUN 设备
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)

    # 配置 TUN 设备
    # struct ifreq 中 ifr_name 最多 16 字节
    # IFF_TUN: TUN 设备 (IP 层)
    # IFF_NO_PI: 不需要 packet info 前缀
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

    print(f"[✓] TUN 设备 '{name}' 创建成功 (fd={tun_fd})")
    return tun_fd


def configure_tun(name: str, ip: str, netmask: str = '255.255.255.0'):
    """配置 TUN 设备的 IP 地址并启动"""
    # 设置 IP 地址
    subprocess.run(['ip', 'addr', 'add', f'{ip}/24', 'dev', name], check=True)
    # 启动接口
    subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)

    print(f"[✓] 配置 {name}: IP={ip}/24, 状态=UP")

    # 显示路由
    result = subprocess.run(['ip', 'route', 'show', 'dev', name],
                           capture_output=True, text=True)
    print(f"[✓] 路由: {result.stdout.strip()}")


def parse_ip_packet(data: bytes) -> dict:
    """解析 IP 包的关键字段"""
    if len(data) < 20:
        return {}

    version = data[0] >> 4
    ihl = (data[0] & 0x0F) * 4
    total_length = struct.unpack('!H', data[2:4])[0]
    protocol = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

    return {
        'version': version,
        'header_len': ihl,
        'total_len': total_length,
        'protocol': proto_map.get(protocol, str(protocol)),
        'protocol_num': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'payload': data[ihl:],
    }


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    tun_name = 'tun0'
    tun_ip = '10.0.0.1'

    print("=" * 60)
    print("TUN 设备创建与数据包读取演示")
    print("=" * 60)
    print()

    # 创建并配置 TUN 设备
    tun_fd = create_tun(tun_name)
    configure_tun(tun_name, tun_ip)

    print()
    print(f"[*] 开始监听 TUN 设备上的 IP 数据包...")
    print(f"[*] 在另一个终端执行: ping 10.0.0.2")
    print(f"[*] 按 Ctrl+C 停止")
    print()

    # 添加指向 TUN 的路由 (让 10.0.0.0/24 的流量走 TUN)
    subprocess.run(['ip', 'route', 'add', '10.0.0.0/24', 'dev', tun_name],
                   capture_output=True)

    packet_count = 0
    try:
        while True:
            # 从 TUN 读取 IP 包
            data = os.read(tun_fd, 4096)
            packet_count += 1

            info = parse_ip_packet(data)
            if info:
                print(f"[包 #{packet_count}] {info['src_ip']} → {info['dst_ip']} "
                      f"协议={info['protocol']} 长度={info['total_len']}")

                # 如果是 ICMP，解析 ICMP 类型
                if info['protocol_num'] == 1 and len(info['payload']) >= 2:
                    icmp_type = info['payload'][0]
                    icmp_code = info['payload'][1]
                    type_names = {0: 'Echo Reply', 8: 'Echo Request'}
                    print(f"        ICMP Type={icmp_type} "
                          f"({type_names.get(icmp_type, 'Other')}) "
                          f"Code={icmp_code}")

            if packet_count >= 20:
                print(f"\n已捕获 {packet_count} 个包，停止")
                break

    except KeyboardInterrupt:
        print(f"\n停止，共捕获 {packet_count} 个包")
    finally:
        os.close(tun_fd)
        # 清理：删除 TUN 设备会自动完成（关闭 fd 时）
        print(f"[✓] TUN 设备已关闭")


if __name__ == '__main__':
    main()
