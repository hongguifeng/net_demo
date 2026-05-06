#!/usr/bin/env python3
"""
简化版 VPN 实现 - TUN + ChaCha20-Poly1305 加密隧道

原理：
  这是一个教学用的简化 VPN，展示 VPN 的核心工作流程：
  1. 创建 TUN 虚拟网卡
  2. 通过 ECDH 协商共享密钥
  3. 从 TUN 读取 IP 包，加密后通过 UDP 发送
  4. 从 UDP 接收密文，解密后写入 TUN

  数据流：
  应用程序 → 内核路由 → TUN → 加密 → UDP → 网络
                                              ↓
  应用程序 ← 内核路由 ← TUN ← 解密 ← UDP ← 网络

  包格式：
  ┌──────────┬──────────────┬────────────────────────────┐
  │ Type (1) │ Counter (8)  │ Encrypted Payload + Tag    │
  └──────────┴──────────────┴────────────────────────────┘
  Type: 1=Handshake, 2=Data
  Counter: 用作 nonce，防重放

运行方式：
  # 终端1 (服务端):
  sudo python3 simple_vpn.py server

  # 终端2 (客户端):
  sudo python3 simple_vpn.py client

  # 终端3 (测试):
  ping 10.7.0.1  (从客户端 ping 服务端的 VPN IP)

验证方法：
  1. ping 通说明 VPN 隧道工作
  2. 用 tcpdump 看 UDP 端口的流量是加密的
     sudo tcpdump -i lo -X udp port 51820
"""

import os
import sys
import struct
import fcntl
import socket
import threading
import time
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# 消息类型
MSG_HANDSHAKE = 1
MSG_DATA = 2


def create_tun(name: str) -> int:
    """创建 TUN 设备"""
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    return tun_fd


def configure_interface(name: str, ip: str):
    """配置网络接口"""
    import subprocess
    subprocess.run(['ip', 'addr', 'add', f'{ip}/24', 'dev', name],
                   check=True, capture_output=True)
    subprocess.run(['ip', 'link', 'set', name, 'mtu', '1400', 'up'],
                   check=True, capture_output=True)


class SimpleVPN:
    """
    简化版 VPN

    安全机制：
    - ECDH 密钥交换 (Curve25519)
    - AEAD 加密 (ChaCha20-Poly1305)
    - Nonce = counter (防重放)
    """

    def __init__(self, role: str, listen_port: int = 51820,
                 peer_addr: tuple = None):
        self.role = role  # 'server' or 'client'
        self.listen_port = listen_port
        self.peer_addr = peer_addr

        # 密钥
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.cipher = None

        # 计数器 (用作 nonce)
        self.tx_counter = 0
        self.rx_counter = 0

        # 统计
        self.stats = {
            'tx_packets': 0, 'rx_packets': 0,
            'tx_bytes': 0, 'rx_bytes': 0
        }

        self.running = False

    def get_public_key_bytes(self) -> bytes:
        """获取公钥的原始字节"""
        return self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    def derive_keys(self, peer_public_bytes: bytes):
        """从 ECDH 共享密钥派生加密密钥"""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)

        # ECDH
        shared_secret = self.private_key.exchange(peer_public)

        # HKDF 派生 256-bit 密钥
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'simple-vpn-salt',
            info=b'simple-vpn-data-key',
        ).derive(shared_secret)

        self.cipher = ChaCha20Poly1305(self.shared_key)
        print(f"  [✓] 密钥协商完成，共享密钥已派生")

    def encrypt_packet(self, plaintext: bytes) -> bytes:
        """
        加密 IP 包

        格式: [type(1)] [counter(8)] [encrypted_data + auth_tag(16)]
        """
        # Nonce: 4 bytes zero + 8 bytes counter (12 bytes total)
        nonce = struct.pack('<I', 0) + struct.pack('<Q', self.tx_counter)
        self.tx_counter += 1

        ciphertext = self.cipher.encrypt(nonce, plaintext, None)

        # 组装消息
        msg = struct.pack('!BQ', MSG_DATA, self.tx_counter - 1) + ciphertext
        return msg

    def decrypt_packet(self, data: bytes) -> bytes:
        """
        解密数据包

        验证：
        1. 消息类型
        2. Counter 必须大于上次（防重放）
        3. AEAD 认证
        """
        if len(data) < 9:
            return b''

        msg_type, counter = struct.unpack('!BQ', data[:9])

        if msg_type != MSG_DATA:
            return b''

        # 防重放检查 (简化版: counter 必须递增)
        if counter < self.rx_counter:
            print(f"  [!] 防重放: 丢弃旧包 counter={counter} < {self.rx_counter}")
            return b''
        self.rx_counter = counter + 1

        # 解密
        nonce = struct.pack('<I', 0) + struct.pack('<Q', counter)
        try:
            plaintext = self.cipher.decrypt(nonce, data[9:], None)
            return plaintext
        except Exception as e:
            print(f"  [!] 解密失败 (可能被篡改): {e}")
            return b''

    def handshake(self, sock: socket.socket):
        """
        简化握手: 交换公钥

        真实 VPN (WireGuard) 的握手更复杂，包括:
        - Noise IK 协议
        - 时间戳防重放
        - Cookie 防 DoS
        """
        my_pub = self.get_public_key_bytes()

        if self.role == 'server':
            # 等待客户端公钥
            print("  [*] 等待客户端握手...")
            data, addr = sock.recvfrom(1024)
            if data[0] == MSG_HANDSHAKE:
                peer_pub = data[1:33]
                self.peer_addr = addr
                print(f"  [←] 收到客户端公钥 from {addr}")

                # 发送自己的公钥
                sock.sendto(struct.pack('B', MSG_HANDSHAKE) + my_pub, addr)
                print(f"  [→] 发送服务端公钥")

                self.derive_keys(peer_pub)
        else:
            # 发送公钥给服务端
            sock.sendto(struct.pack('B', MSG_HANDSHAKE) + my_pub, self.peer_addr)
            print(f"  [→] 发送客户端公钥 to {self.peer_addr}")

            # 接收服务端公钥
            data, addr = sock.recvfrom(1024)
            if data[0] == MSG_HANDSHAKE:
                peer_pub = data[1:33]
                print(f"  [←] 收到服务端公钥")
                self.derive_keys(peer_pub)

    def run(self):
        """运行 VPN"""
        # 配置
        if self.role == 'server':
            tun_name = 'vpn0'
            tun_ip = '10.7.0.1'
        else:
            tun_name = 'vpn0'
            tun_ip = '10.7.0.2'

        print(f"\n[配置]")
        print(f"  角色:     {self.role}")
        print(f"  TUN:      {tun_name} ({tun_ip}/24)")
        print(f"  UDP 端口: {self.listen_port}")
        print()

        # 创建 TUN
        tun_fd = create_tun(tun_name)
        configure_interface(tun_name, tun_ip)
        print(f"  [✓] TUN 设备已创建")

        # 创建 UDP 套接字
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(('0.0.0.0', self.listen_port))
        udp_sock.setblocking(False)
        print(f"  [✓] UDP 套接字绑定到 :{self.listen_port}")
        print()

        # 握手
        print("[握手]")
        udp_sock.setblocking(True)
        udp_sock.settimeout(10)
        try:
            self.handshake(udp_sock)
        except socket.timeout:
            print("  [✗] 握手超时")
            os.close(tun_fd)
            udp_sock.close()
            return
        udp_sock.setblocking(False)

        print()
        print("[运行] VPN 隧道已建立，开始转发数据包")
        print(f"  对端地址: {self.peer_addr}")
        print(f"  按 Ctrl+C 停止")
        print()

        self.running = True
        try:
            import select
            while self.running:
                readable, _, _ = select.select([tun_fd, udp_sock], [], [], 1.0)

                for fd in readable:
                    if fd == tun_fd:
                        # TUN → 加密 → UDP
                        packet = os.read(tun_fd, 1500)
                        if packet and self.cipher:
                            encrypted = self.encrypt_packet(packet)
                            udp_sock.sendto(encrypted, self.peer_addr)
                            self.stats['tx_packets'] += 1
                            self.stats['tx_bytes'] += len(packet)

                            if self.stats['tx_packets'] % 10 == 1:
                                src = socket.inet_ntoa(packet[12:16]) if len(packet) >= 20 else '?'
                                dst = socket.inet_ntoa(packet[16:20]) if len(packet) >= 20 else '?'
                                print(f"  [TX] {src}→{dst} "
                                      f"{len(packet)}B → 加密 → {len(encrypted)}B")

                    elif fd == udp_sock:
                        # UDP → 解密 → TUN
                        try:
                            data, addr = udp_sock.recvfrom(2048)
                            if data and self.cipher:
                                decrypted = self.decrypt_packet(data)
                                if decrypted:
                                    os.write(tun_fd, decrypted)
                                    self.stats['rx_packets'] += 1
                                    self.stats['rx_bytes'] += len(decrypted)

                                    if self.stats['rx_packets'] % 10 == 1:
                                        src = socket.inet_ntoa(decrypted[12:16]) if len(decrypted) >= 20 else '?'
                                        dst = socket.inet_ntoa(decrypted[16:20]) if len(decrypted) >= 20 else '?'
                                        print(f"  [RX] {src}→{dst} "
                                              f"{len(data)}B → 解密 → {len(decrypted)}B")
                        except BlockingIOError:
                            pass

        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            os.close(tun_fd)
            udp_sock.close()

            print(f"\n[统计]")
            print(f"  发送: {self.stats['tx_packets']} pkts, "
                  f"{self.stats['tx_bytes']} bytes")
            print(f"  接收: {self.stats['rx_packets']} pkts, "
                  f"{self.stats['rx_bytes']} bytes")
            print(f"  [✓] VPN 已关闭")


def main():
    if os.geteuid() != 0:
        print("错误：需要 root 权限")
        sys.exit(1)

    print("=" * 70)
    print("简化版 VPN (TUN + ChaCha20-Poly1305)")
    print("=" * 70)

    if len(sys.argv) < 2:
        print("\n用法:")
        print("  sudo python3 simple_vpn.py server    # 启动服务端")
        print("  sudo python3 simple_vpn.py client    # 启动客户端")
        print("\n测试:")
        print("  ping 10.7.0.1    # 从客户端 ping 服务端")
        sys.exit(0)

    role = sys.argv[1].lower()

    if role == 'server':
        vpn = SimpleVPN(role='server', listen_port=51820)
    elif role == 'client':
        vpn = SimpleVPN(role='client', listen_port=51821,
                        peer_addr=('127.0.0.1', 51820))
    else:
        print(f"未知角色: {role}")
        sys.exit(1)

    vpn.run()


if __name__ == '__main__':
    main()
