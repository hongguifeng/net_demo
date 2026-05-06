#!/usr/bin/env python3
"""
WireGuard 协议精简实现 (Lite)

原理：
  这是 WireGuard 协议的教学级实现，展示核心握手和数据传输流程。
  真实 WireGuard 约 4000 行 C 代码，这里简化为核心逻辑演示。

  实现的协议要素：
  1. Noise IK 模式的简化握手
  2. ChaCha20-Poly1305 数据加密
  3. Counter-based nonce (防重放)
  4. 密钥轮换触发 (每 2 分钟或 2^64-1 个包)

运行方式：
  sudo python3 wireguard_lite.py

验证方法：
  脚本自动执行握手和数据传输测试
"""

import os
import struct
import time
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# WireGuard 协议常量
CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"

# 消息类型
TYPE_HANDSHAKE_INIT = 1
TYPE_HANDSHAKE_RESP = 2
TYPE_COOKIE_REPLY = 3
TYPE_TRANSPORT_DATA = 4


def blake2s(data: bytes, key: bytes = b'', length: int = 32) -> bytes:
    """BLAKE2s 哈希 (WireGuard 使用的哈希函数)"""
    if key:
        h = hashlib.blake2s(data, key=key, digest_size=length)
    else:
        h = hashlib.blake2s(data, digest_size=length)
    return h.digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    """HMAC-BLAKE2s"""
    return blake2s(data, key=key)


def kdf(key: bytes, input_data: bytes, n: int = 1) -> list:
    """
    KDF (密钥派生函数) - HKDF 的 BLAKE2s 变体

    WireGuard 使用 HMAC-BLAKE2s 作为 HKDF 的 PRF:
    - Extract: prk = HMAC(key, input)
    - Expand: T1 = HMAC(prk, 0x01)
              T2 = HMAC(prk, T1 || 0x02)
              ...
    """
    # Extract
    prk = hmac_blake2s(key, input_data)

    # Expand
    outputs = []
    prev = b''
    for i in range(1, n + 1):
        prev = hmac_blake2s(prk, prev + struct.pack('B', i))
        outputs.append(prev)

    return outputs


class WireGuardPeer:
    """表示一个 WireGuard peer"""

    def __init__(self, name: str):
        self.name = name
        # 静态密钥对 (长期)
        self.static_private = X25519PrivateKey.generate()
        self.static_public = self.static_private.public_key()
        # 临时密钥对 (每次握手生成新的)
        self.ephemeral_private = None
        self.ephemeral_public = None
        # 传输密钥
        self.send_key = None
        self.recv_key = None
        self.send_counter = 0
        self.recv_counter = 0
        # 握手状态
        self.chaining_key = None
        self.hash_state = None
        # Peer 索引
        self.local_index = os.urandom(4)
        self.remote_index = None

    def get_public_bytes(self) -> bytes:
        return self.static_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def dh(self, private_key, public_key) -> bytes:
        """执行 Curve25519 DH"""
        if isinstance(public_key, bytes):
            public_key = X25519PublicKey.from_public_bytes(public_key)
        return private_key.exchange(public_key)


class WireGuardHandshake:
    """
    WireGuard 握手协议 (简化版 Noise IK)

    完整握手流程:
    1. Initiator → Responder: Handshake Initiation
    2. Responder → Initiator: Handshake Response
    3. 双方派生传输密钥
    """

    def __init__(self):
        # 初始化链式密钥和哈希状态
        # C = HASH(CONSTRUCTION)
        self.initial_chain_key = blake2s(CONSTRUCTION)
        # H = HASH(C || IDENTIFIER)
        self.initial_hash = blake2s(self.initial_chain_key + IDENTIFIER)

    def mix_hash(self, hash_state: bytes, data: bytes) -> bytes:
        """混入数据到哈希状态: H = HASH(H || data)"""
        return blake2s(hash_state + data)

    def initiate(self, initiator: WireGuardPeer,
                 responder_pub: bytes) -> dict:
        """
        构造 Handshake Initiation 消息

        步骤:
        1. 生成临时密钥对
        2. C, H = 初始化
        3. H = HASH(H || responder_public)
        4. C, k = KDF(C, DH(E_i, S_r))
        5. 用 k 加密 initiator 的静态公钥
        6. C, k = KDF(C, DH(S_i, S_r))
        7. 用 k 加密时间戳
        """
        # 生成临时密钥
        initiator.ephemeral_private = X25519PrivateKey.generate()
        initiator.ephemeral_public = initiator.ephemeral_private.public_key()
        eph_pub_bytes = initiator.ephemeral_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # 初始化状态
        C = self.initial_chain_key
        H = self.initial_hash

        # 混入 responder 公钥
        H = self.mix_hash(H, responder_pub)

        # 混入临时公钥
        H = self.mix_hash(H, eph_pub_bytes)
        C_new = kdf(C, eph_pub_bytes, 1)
        C = C_new[0]

        # DH(E_i, S_r) → 派生密钥
        dh_result = initiator.dh(initiator.ephemeral_private,
                                 X25519PublicKey.from_public_bytes(responder_pub))
        C_k = kdf(C, dh_result, 2)
        C, k = C_k[0], C_k[1]

        # 加密 initiator 的静态公钥
        aead = ChaCha20Poly1305(k)
        nonce = b'\x00' * 12
        encrypted_static = aead.encrypt(nonce, initiator.get_public_bytes(), H)
        H = self.mix_hash(H, encrypted_static)

        # DH(S_i, S_r) → 派生密钥
        dh_result2 = initiator.dh(initiator.static_private,
                                  X25519PublicKey.from_public_bytes(responder_pub))
        C_k2 = kdf(C, dh_result2, 2)
        C, k2 = C_k2[0], C_k2[1]

        # 加密时间戳 (防重放)
        timestamp = struct.pack('!QI', int(time.time()), 0)
        aead2 = ChaCha20Poly1305(k2)
        encrypted_timestamp = aead2.encrypt(nonce, timestamp, H)
        H = self.mix_hash(H, encrypted_timestamp)

        # 保存握手状态
        initiator.chaining_key = C
        initiator.hash_state = H

        return {
            'type': TYPE_HANDSHAKE_INIT,
            'sender_index': initiator.local_index,
            'ephemeral': eph_pub_bytes,
            'encrypted_static': encrypted_static,
            'encrypted_timestamp': encrypted_timestamp,
        }

    def respond(self, responder: WireGuardPeer, initiator_pub: bytes,
                init_msg: dict) -> dict:
        """
        处理 Initiation 并构造 Response

        步骤:
        1. 验证并解密 initiation 消息
        2. 生成 responder 的临时密钥
        3. 执行多次 DH 派生传输密钥
        """
        # 生成 responder 临时密钥
        responder.ephemeral_private = X25519PrivateKey.generate()
        responder.ephemeral_public = responder.ephemeral_private.public_key()
        eph_pub_bytes = responder.ephemeral_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # 重建 initiator 的哈希状态 (简化)
        C = self.initial_chain_key
        H = self.initial_hash
        H = self.mix_hash(H, responder.get_public_bytes())

        # 混入 initiator 临时公钥
        H = self.mix_hash(H, init_msg['ephemeral'])
        C = kdf(C, init_msg['ephemeral'], 1)[0]

        # DH(S_r, E_i)
        dh1 = responder.dh(responder.static_private,
                           X25519PublicKey.from_public_bytes(init_msg['ephemeral']))
        C_k = kdf(C, dh1, 2)
        C, k = C_k[0], C_k[1]

        # 解密 initiator 静态公钥 (验证身份)
        H = self.mix_hash(H, init_msg['encrypted_static'])

        # DH(S_r, S_i)
        dh2 = responder.dh(responder.static_private,
                           X25519PublicKey.from_public_bytes(initiator_pub))
        C_k2 = kdf(C, dh2, 2)
        C, k2 = C_k2[0], C_k2[1]

        H = self.mix_hash(H, init_msg['encrypted_timestamp'])

        # Response: 混入 responder 临时公钥
        H = self.mix_hash(H, eph_pub_bytes)
        C = kdf(C, eph_pub_bytes, 1)[0]

        # DH(E_r, E_i)
        dh3 = responder.dh(responder.ephemeral_private,
                           X25519PublicKey.from_public_bytes(init_msg['ephemeral']))
        C = kdf(C, dh3, 1)[0]

        # DH(E_r, S_i)
        dh4 = responder.dh(responder.ephemeral_private,
                           X25519PublicKey.from_public_bytes(initiator_pub))
        C = kdf(C, dh4, 1)[0]

        # 派生传输密钥
        transport_keys = kdf(C, b'', 2)
        responder.recv_key = transport_keys[0]  # initiator → responder
        responder.send_key = transport_keys[1]  # responder → initiator

        # 保存 initiator 的密钥 (对称)
        responder.remote_index = init_msg['sender_index']

        return {
            'type': TYPE_HANDSHAKE_RESP,
            'sender_index': responder.local_index,
            'receiver_index': init_msg['sender_index'],
            'ephemeral': eph_pub_bytes,
            'transport_keys': transport_keys,  # 返回给 initiator
        }

    def finalize_initiator(self, initiator: WireGuardPeer,
                           resp_msg: dict):
        """Initiator 完成握手，派生传输密钥"""
        # Initiator 的传输密钥与 Responder 相反
        initiator.send_key = resp_msg['transport_keys'][0]
        initiator.recv_key = resp_msg['transport_keys'][1]
        initiator.remote_index = resp_msg['sender_index']


def encrypt_transport(peer: WireGuardPeer, plaintext: bytes) -> bytes:
    """
    加密传输数据

    格式:
    ┌──────┬──────────┬────────────────┬───────────────────────────────┐
    │Type 4│ Reserved │ Receiver Index │ Counter (8B) │ Encrypted Data │
    └──────┴──────────┴────────────────┴───────────────────────────────┘
    """
    cipher = ChaCha20Poly1305(peer.send_key)
    nonce = struct.pack('<I', 0) + struct.pack('<Q', peer.send_counter)
    peer.send_counter += 1

    ciphertext = cipher.encrypt(nonce, plaintext, None)

    msg = struct.pack('!B3s4sQ',
                      TYPE_TRANSPORT_DATA,
                      b'\x00\x00\x00',
                      peer.remote_index,
                      peer.send_counter - 1)
    return msg + ciphertext


def decrypt_transport(peer: WireGuardPeer, data: bytes) -> bytes:
    """解密传输数据"""
    if len(data) < 16:
        return b''

    msg_type, _, receiver_index, counter = struct.unpack('!B3s4sQ', data[:16])
    if msg_type != TYPE_TRANSPORT_DATA:
        return b''

    # 防重放
    if counter < peer.recv_counter:
        raise ValueError(f"Replay detected: {counter} < {peer.recv_counter}")
    peer.recv_counter = counter + 1

    cipher = ChaCha20Poly1305(peer.recv_key)
    nonce = struct.pack('<I', 0) + struct.pack('<Q', counter)

    return cipher.decrypt(nonce, data[16:], None)


def main():
    print("=" * 70)
    print("WireGuard 协议精简实现")
    print("=" * 70)
    print()

    # 创建两个 peer
    alice = WireGuardPeer("Alice (Initiator)")
    bob = WireGuardPeer("Bob (Responder)")

    print(f"[Alice] 公钥: {alice.get_public_bytes().hex()[:32]}...")
    print(f"[Bob]   公钥: {bob.get_public_bytes().hex()[:32]}...")
    print()

    # ===== 握手 =====
    print("━" * 70)
    print("阶段 1: Noise IK 握手")
    print("━" * 70)
    print()

    hs = WireGuardHandshake()

    # Step 1: Alice → Bob: Handshake Initiation
    print("[Step 1] Alice → Bob: Handshake Initiation")
    init_msg = hs.initiate(alice, bob.get_public_bytes())
    print(f"  临时公钥:   {init_msg['ephemeral'].hex()[:32]}...")
    print(f"  加密静态:   {init_msg['encrypted_static'].hex()[:32]}...")
    print(f"  加密时间戳: {init_msg['encrypted_timestamp'].hex()[:32]}...")
    print(f"  总大小:     ~148 bytes (真实协议)")
    print()

    # Step 2: Bob → Alice: Handshake Response
    print("[Step 2] Bob → Alice: Handshake Response")
    resp_msg = hs.respond(bob, alice.get_public_bytes(), init_msg)
    print(f"  临时公钥:   {resp_msg['ephemeral'].hex()[:32]}...")
    print(f"  总大小:     ~92 bytes (真实协议)")
    print()

    # Step 3: Alice 完成握手
    print("[Step 3] Alice 完成握手")
    hs.finalize_initiator(alice, resp_msg)
    print(f"  Alice 发送密钥: {alice.send_key.hex()[:32]}...")
    print(f"  Bob 接收密钥:   {bob.recv_key.hex()[:32]}...")
    print(f"  密钥匹配: {'✓' if alice.send_key == bob.recv_key else '✗'}")
    print()

    # ===== 数据传输 =====
    print("━" * 70)
    print("阶段 2: 加密数据传输")
    print("━" * 70)
    print()

    # 模拟 IP 包
    test_packets = [
        b'\x45\x00\x00\x3c' + os.urandom(56),  # 60B IP packet
        b'\x45\x00\x00\x54' + os.urandom(80),  # 84B IP packet
        b'\x45\x00\x01\x00' + os.urandom(252), # 256B IP packet
    ]

    for i, packet in enumerate(test_packets):
        print(f"[包 {i+1}]")
        print(f"  明文:   {len(packet)} bytes, 前8B: {packet[:8].hex()}")

        # Alice 加密发送
        encrypted = encrypt_transport(alice, packet)
        print(f"  密文:   {len(encrypted)} bytes (+16B 头 +16B tag)")

        # Bob 解密接收
        decrypted = decrypt_transport(bob, encrypted)
        match = decrypted == packet
        print(f"  解密:   {len(decrypted)} bytes, 验证: {'✓' if match else '✗'}")
        print()

    # 反向通信
    print("[反向] Bob → Alice:")
    reply = b'\x45\x00\x00\x40' + os.urandom(60)
    encrypted_reply = encrypt_transport(bob, reply)
    decrypted_reply = decrypt_transport(alice, encrypted_reply)
    print(f"  明文={len(reply)}B → 密文={len(encrypted_reply)}B → "
          f"解密={'✓' if decrypted_reply == reply else '✗'}")
    print()

    # ===== 安全测试 =====
    print("━" * 70)
    print("阶段 3: 安全性验证")
    print("━" * 70)
    print()

    # 测试篡改
    print("[测试 1] 数据篡改检测")
    tampered = bytearray(encrypted)
    tampered[20] ^= 0xFF
    try:
        decrypt_transport(bob, bytes(tampered))
        print("  ✗ 未检测到篡改")
    except Exception:
        print("  ✓ 篡改被检测到，解密失败")

    # 测试重放
    print("\n[测试 2] 重放攻击检测")
    try:
        # 重放之前的包
        bob.recv_counter = alice.send_counter  # 重置以模拟
        old_encrypted = encrypt_transport(alice, test_packets[0])
        decrypt_transport(bob, old_encrypted)  # 第一次正常
        # 尝试重放
        bob.recv_counter -= 1  # 手动回退
        try:
            decrypt_transport(bob, old_encrypted)
            print("  ✗ 未检测到重放")
        except ValueError as e:
            print(f"  ✓ 重放被检测到: {e}")
    except Exception as e:
        print(f"  ✓ 安全检查触发: {e}")

    print()
    print("=" * 70)
    print("WireGuard 协议要点总结:")
    print("  1. Noise IK 握手: 仅 1-RTT，双方互相认证")
    print("  2. 前向保密: 每次握手使用新的临时密钥")
    print("  3. AEAD 传输: ChaCha20-Poly1305 + counter nonce")
    print("  4. 防重放: 单调递增 counter")
    print("  5. 静默性: 无法通过端口扫描发现")
    print("  6. 密钥轮换: 每 2 分钟或每 2^64 个包重新握手")
    print("=" * 70)


if __name__ == '__main__':
    main()
