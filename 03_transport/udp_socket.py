#!/usr/bin/env python3
"""
UDP 回显服务器和客户端

原理：
  UDP 是无连接协议，不需要握手即可直接发送数据。
  这个演示实现了一个 UDP echo server，帮助理解 UDP 通信模型。

  UDP 头部 (仅 8 字节):
  ┌──────────────┬──────────────┬──────────────┬──────────────┐
  │ Src Port (2) │ Dst Port (2) │ Length (2)   │ Checksum (2) │
  └──────────────┴──────────────┴──────────────┴──────────────┘

  UDP vs TCP:
  - 无连接：无需握手，直接发送
  - 不可靠：不保证到达、不保证顺序
  - 无流控：发送方可以任意速率发送
  - 低延迟：没有握手和确认的开销
  - 适用场景：DNS、视频流、游戏、IoT

运行方式：
  # 终端1: 启动服务器
  python3 udp_socket.py server

  # 终端2: 启动客户端
  python3 udp_socket.py client

验证方法：
  1. 客户端发送消息，服务器返回相同消息（回显）
  2. 使用 tcpdump 查看 UDP 包:
     sudo tcpdump -i lo -n udp port 8888
"""

import socket
import sys
import time
import struct
import threading


def udp_echo_server(host: str = '127.0.0.1', port: int = 8888):
    """
    UDP 回显服务器

    特点：
    - 无需 listen() 和 accept()
    - recvfrom() 返回数据和发送方地址
    - 可以同时服务多个客户端
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    print(f"[Server] UDP Echo Server 启动在 {host}:{port}")
    print(f"[Server] 等待数据...")
    print()

    packet_count = 0
    try:
        while True:
            # recvfrom 同时返回数据和客户端地址
            data, client_addr = sock.recvfrom(4096)
            packet_count += 1

            print(f"[Server] #{packet_count} 收到 {len(data)} bytes "
                  f"来自 {client_addr[0]}:{client_addr[1]}")
            print(f"         内容: {data.decode('utf-8', errors='replace')}")

            # 回显：将相同数据发回客户端
            response = data
            sock.sendto(response, client_addr)
            print(f"         回显已发送")
            print()

    except KeyboardInterrupt:
        print(f"\n[Server] 停止. 共处理 {packet_count} 个数据包")
    finally:
        sock.close()


def udp_echo_client(host: str = '127.0.0.1', port: int = 8888):
    """
    UDP 回显客户端

    特点：
    - 无需 connect() (但可以用 connect 简化)
    - sendto() 每次指定目标地址
    - 可能丢包，需要应用层处理
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    print(f"[Client] UDP Echo Client")
    print(f"[Client] 目标: {host}:{port}")
    print()

    messages = [
        "Hello UDP!",
        "UDP is connectionless",
        "No handshake needed",
        "Fast but unreliable",
        "Great for real-time apps",
    ]

    stats = {'sent': 0, 'received': 0, 'lost': 0, 'total_rtt': 0}

    for msg in messages:
        data = msg.encode('utf-8')

        send_time = time.time()
        sock.sendto(data, (host, port))
        stats['sent'] += 1

        try:
            response, server_addr = sock.recvfrom(4096)
            recv_time = time.time()
            rtt = (recv_time - send_time) * 1000  # ms

            stats['received'] += 1
            stats['total_rtt'] += rtt

            print(f"[Client] 发送: '{msg}'")
            print(f"         回显: '{response.decode()}'")
            print(f"         RTT:  {rtt:.3f} ms")
            print(f"         匹配: {'✓' if response == data else '✗'}")
            print()

        except socket.timeout:
            stats['lost'] += 1
            print(f"[Client] 发送: '{msg}' → 超时未收到回复 (丢包?)")
            print()

        time.sleep(0.1)

    # 统计
    print("=" * 50)
    print("[统计]")
    print(f"  发送: {stats['sent']} 包")
    print(f"  接收: {stats['received']} 包")
    print(f"  丢失: {stats['lost']} 包 ({stats['lost']/stats['sent']*100:.1f}%)")
    if stats['received'] > 0:
        avg_rtt = stats['total_rtt'] / stats['received']
        print(f"  平均 RTT: {avg_rtt:.3f} ms")
    print("=" * 50)

    sock.close()


def demo_udp_broadcast():
    """
    演示 UDP 广播

    广播地址 255.255.255.255 或子网广播地址
    同一子网内所有主机都能接收广播消息
    """
    print("\n" + "=" * 50)
    print("UDP 广播演示")
    print("=" * 50)

    # 创建广播套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    broadcast_addr = '255.255.255.255'
    port = 9999

    message = b'UDP Broadcast Test'
    sock.sendto(message, (broadcast_addr, port))
    print(f"[Broadcast] 发送广播消息到 {broadcast_addr}:{port}")
    print(f"[Broadcast] 内容: {message.decode()}")
    print(f"[Broadcast] 需要设置 SO_BROADCAST 套接字选项")

    sock.close()


def demo_udp_multicast():
    """
    演示 UDP 多播 (Multicast)

    多播地址范围: 224.0.0.0 ~ 239.255.255.255
    主机通过加入多播组来接收多播消息
    """
    print("\n" + "=" * 50)
    print("UDP 多播演示 (Multicast)")
    print("=" * 50)

    multicast_group = '239.1.1.1'
    port = 5007

    # 发送方
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 设置 TTL (多播 TTL 默认为 1，仅限本地子网)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    message = b'Multicast message!'
    sock.sendto(message, (multicast_group, port))
    print(f"[Multicast] 发送到组 {multicast_group}:{port}")
    print(f"[Multicast] 内容: {message.decode()}")
    print(f"[Multicast] TTL=2 (可跨一个路由器)")
    print()
    print("[Multicast] 接收方需要加入多播组:")
    print(f"  mreq = struct.pack('4sL', "
          f"socket.inet_aton('{multicast_group}'), socket.INADDR_ANY)")
    print(f"  sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)")

    sock.close()


def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python3 udp_socket.py server     # 启动回显服务器")
        print("  python3 udp_socket.py client     # 启动客户端")
        print("  python3 udp_socket.py broadcast  # 广播演示")
        print("  python3 udp_socket.py multicast  # 多播演示")
        print("  python3 udp_socket.py demo       # 内置演示 (自动启停)")
        sys.exit(0)

    mode = sys.argv[1].lower()

    if mode == 'server':
        udp_echo_server()
    elif mode == 'client':
        udp_echo_client()
    elif mode == 'broadcast':
        demo_udp_broadcast()
    elif mode == 'multicast':
        demo_udp_multicast()
    elif mode == 'demo':
        # 自动演示：在线程中启动服务器，然后运行客户端
        print("=" * 50)
        print("UDP Echo 自动演示")
        print("=" * 50)
        print()

        server_thread = threading.Thread(target=udp_echo_server, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        udp_echo_client()
        demo_udp_broadcast()
        demo_udp_multicast()
    else:
        print(f"未知模式: {mode}")
        sys.exit(1)


if __name__ == '__main__':
    main()
