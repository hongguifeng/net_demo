#!/usr/bin/env python3
"""
TCP 三次握手 - 使用原始套接字手动实现

原理：
  正常情况下内核的 TCP 栈自动完成三次握手。
  这里我们用原始套接字手动构造 SYN/ACK 包，
  从底层理解 TCP 连接建立的完整过程。

  三次握手：
  1. Client → Server: SYN (seq=ISN_c)
  2. Server → Client: SYN+ACK (seq=ISN_s, ack=ISN_c+1)
  3. Client → Server: ACK (seq=ISN_c+1, ack=ISN_s+1)

  关键点：
  - ISN (Initial Sequence Number) 应该是随机的，防止序列号预测攻击
  - TCP 校验和需要包含伪头部 (pseudo header)

运行方式：
  # 终端1: 启动一个简单的监听服务
  python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',9999)); s.listen(1); print('listening'); c,a=s.accept(); print(f'connected from {a}'); c.close(); s.close()"

  # 终端2: 运行三次握手
  sudo python3 tcp_handshake.py 127.0.0.1 9999

验证方法：
  sudo tcpdump -i lo -n 'tcp port 9999' -S
"""

import socket
import struct
import sys
import os
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


def build_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int, ack: int, flags: int, window: int = 65535,
                     data: bytes = b'') -> bytes:
    """
    构建 TCP 段

    TCP 校验和计算需要包含伪头部 (Pseudo Header):
    ┌──────────────────┬──────────────────┬──────────┬──────────────┐
    │ Source IP (4B)   │ Dest IP (4B)     │ Zero+Proto│ TCP Length   │
    └──────────────────┴──────────────────┴──────────┴──────────────┘

    参数：
        flags: TCP 标志位
            FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
    """
    # TCP 头部 (20 bytes without options)
    data_offset = 5  # 5 * 4 = 20 bytes (无选项)
    offset_reserved = (data_offset << 4)
    urgent_pointer = 0

    # 先用 checksum=0 构建 TCP 头
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port,        # 源端口
                             dst_port,        # 目的端口
                             seq,             # 序列号
                             ack,             # 确认号
                             offset_reserved, # 数据偏移
                             flags,           # 标志位
                             window,          # 窗口大小
                             0,               # 校验和 (暂时为 0)
                             urgent_pointer)  # 紧急指针

    # 构建伪头部用于校验和计算
    tcp_length = len(tcp_header) + len(data)
    pseudo_header = struct.pack('!4s4sBBH',
                                socket.inet_aton(src_ip),
                                socket.inet_aton(dst_ip),
                                0,       # 保留
                                6,       # 协议号 (TCP=6)
                                tcp_length)

    # 计算校验和 (伪头部 + TCP 头 + 数据)
    checksum = calculate_checksum(pseudo_header + tcp_header + data)

    # 重新打包，填入校验和
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, ack,
                             offset_reserved, flags, window,
                             checksum, urgent_pointer)

    return tcp_header + data


def tcp_flags_to_str(flags: int) -> str:
    """将 TCP 标志位转换为可读字符串"""
    names = []
    if flags & 0x02:
        names.append('SYN')
    if flags & 0x10:
        names.append('ACK')
    if flags & 0x01:
        names.append('FIN')
    if flags & 0x04:
        names.append('RST')
    if flags & 0x08:
        names.append('PSH')
    return '+'.join(names) if names else 'none'


def perform_handshake(target_ip: str, target_port: int):
    """
    执行 TCP 三次握手
    """
    src_port = random.randint(40000, 60000)
    isn = random.randint(0, 0xFFFFFFFF)  # 随机初始序列号

    print(f"\n[配置]")
    print(f"  源端口:      {src_port}")
    print(f"  目标:        {target_ip}:{target_port}")
    print(f"  ISN:         {isn}")
    print()

    # 创建原始套接字
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)

    # 接收套接字
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    recv_sock.settimeout(3)

    src_ip = "127.0.0.1"

    # ============ 第一步: 发送 SYN ============
    print("[步骤 1] 发送 SYN")
    syn_flags = 0x02  # SYN
    syn_packet = build_tcp_packet(src_ip, target_ip, src_port, target_port,
                                  seq=isn, ack=0, flags=syn_flags)

    send_sock.sendto(syn_packet, (target_ip, 0))
    print(f"  → SYN sent: seq={isn}, flags={tcp_flags_to_str(syn_flags)}")

    # ============ 第二步: 接收 SYN+ACK ============
    print("\n[步骤 2] 等待 SYN+ACK...")

    server_isn = None
    try:
        while True:
            data, addr = recv_sock.recvfrom(65535)
            # 解析 IP 头
            ip_header_len = (data[0] & 0x0F) * 4
            tcp_data = data[ip_header_len:]

            # 解析 TCP 头
            tcp_src_port = struct.unpack('!H', tcp_data[0:2])[0]
            tcp_dst_port = struct.unpack('!H', tcp_data[2:4])[0]
            tcp_seq = struct.unpack('!I', tcp_data[4:8])[0]
            tcp_ack = struct.unpack('!I', tcp_data[8:12])[0]
            tcp_flags = tcp_data[13]

            # 过滤：只接收来自目标端口、发往我们端口的包
            if tcp_src_port == target_port and tcp_dst_port == src_port:
                print(f"  ← 收到: seq={tcp_seq}, ack={tcp_ack}, "
                      f"flags={tcp_flags_to_str(tcp_flags)}")

                if tcp_flags & 0x12 == 0x12:  # SYN+ACK
                    server_isn = tcp_seq
                    print(f"  ✓ 收到 SYN+ACK! Server ISN={server_isn}")
                    break
                elif tcp_flags & 0x04:  # RST
                    print(f"  ✗ 收到 RST - 端口未开放或被拒绝")
                    send_sock.close()
                    recv_sock.close()
                    return

    except socket.timeout:
        print("  ✗ 超时 - 未收到 SYN+ACK")
        send_sock.close()
        recv_sock.close()
        return

    # ============ 第三步: 发送 ACK ============
    print(f"\n[步骤 3] 发送 ACK")
    ack_flags = 0x10  # ACK
    ack_packet = build_tcp_packet(src_ip, target_ip, src_port, target_port,
                                  seq=isn + 1, ack=server_isn + 1,
                                  flags=ack_flags)

    send_sock.sendto(ack_packet, (target_ip, 0))
    print(f"  → ACK sent: seq={isn + 1}, ack={server_isn + 1}, "
          f"flags={tcp_flags_to_str(ack_flags)}")

    print(f"\n[✓] 三次握手完成！TCP 连接已建立")
    print(f"    Client ISN: {isn}")
    print(f"    Server ISN: {server_isn}")

    # 发送 RST 关闭连接 (简化处理)
    print(f"\n[清理] 发送 RST 关闭连接")
    rst_packet = build_tcp_packet(src_ip, target_ip, src_port, target_port,
                                  seq=isn + 1, ack=0, flags=0x04)
    send_sock.sendto(rst_packet, (target_ip, 0))

    send_sock.close()
    recv_sock.close()


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

    print("=" * 60)
    print("TCP 三次握手 - 原始套接字实现")
    print("=" * 60)
    print()
    print("注意: 需要先在目标端口启动监听服务:")
    print(f"  python3 -c \"import socket; s=socket.socket(); "
          f"s.bind(('127.0.0.1',{target_port})); s.listen(1); "
          f"print('listening'); c,a=s.accept(); print(f'connected from {{a}}'); "
          f"c.close(); s.close()\"")
    print()
    print("同时建议运行 tcpdump 观察:")
    print(f"  sudo tcpdump -i lo -n 'tcp port {target_port}' -S")

    # 禁止内核自动发送 RST
    # 因为内核看到收到 SYN+ACK 但没有对应的套接字会自动 RST
    print()
    print("[!] 需要阻止内核自动 RST (使用 iptables):")
    print(f"    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST "
          f"-d {target_ip} --dport {target_port} -j DROP")
    print(f"    (完成后记得删除: sudo iptables -D OUTPUT ...)")

    perform_handshake(target_ip, target_port)


if __name__ == '__main__':
    main()
