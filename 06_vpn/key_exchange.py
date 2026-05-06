#!/usr/bin/env python3
"""
Curve25519 密钥交换演示

原理：
  Diffie-Hellman 密钥交换允许两方在不安全信道上协商出共享密钥。
  Curve25519 是现代椭圆曲线 DH (ECDH) 的首选曲线。

  工作流程：
  1. Alice 生成私钥 a，计算公钥 A = a*G (G 是基点)
  2. Bob 生成私钥 b，计算公钥 B = b*G
  3. Alice 和 Bob 交换公钥 (可以在公开信道)
  4. Alice 计算 shared = a*B = a*b*G
  5. Bob 计算 shared = b*A = b*a*G
  6. 双方得到相同的 shared secret！

  安全性：
  - 知道 A 和 B，无法推导出 a*b*G (ECDLP 难题)
  - Curve25519 提供 ~128 位安全强度
  - 抗时序攻击 (常量时间实现)

运行方式：
  python3 key_exchange.py

验证方法：
  观察两端计算出的共享密钥是否相同
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os


def demo_basic_key_exchange():
    """基础 Curve25519 密钥交换"""
    print("=" * 70)
    print("Curve25519 ECDH 密钥交换")
    print("=" * 70)
    print()

    # ===== Alice 端 =====
    print("[Alice] 生成密钥对...")
    alice_private = X25519PrivateKey.generate()
    alice_public = alice_private.public_key()
    alice_pub_bytes = alice_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    print(f"  私钥: (保密)")
    print(f"  公钥: {alice_pub_bytes.hex()}")
    print()

    # ===== Bob 端 =====
    print("[Bob] 生成密钥对...")
    bob_private = X25519PrivateKey.generate()
    bob_public = bob_private.public_key()
    bob_pub_bytes = bob_public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    print(f"  私钥: (保密)")
    print(f"  公钥: {bob_pub_bytes.hex()}")
    print()

    # ===== 密钥交换 =====
    print("[交换] Alice 和 Bob 交换公钥 (可以在公开信道)")
    print()

    # Alice 用自己的私钥 + Bob 的公钥计算共享密钥
    alice_shared = alice_private.exchange(bob_public)
    print(f"[Alice] 计算共享密钥: {alice_shared.hex()}")

    # Bob 用自己的私钥 + Alice 的公钥计算共享密钥
    bob_shared = bob_private.exchange(alice_public)
    print(f"[Bob]   计算共享密钥: {bob_shared.hex()}")
    print()

    # 验证
    assert alice_shared == bob_shared, "共享密钥不匹配！"
    print(f"[✓] 共享密钥匹配！长度={len(alice_shared)} bytes")
    print()

    return alice_shared


def demo_key_derivation(shared_secret: bytes):
    """从共享密钥派生加密密钥"""
    print("=" * 70)
    print("密钥派生 (HKDF)")
    print("=" * 70)
    print()
    print("原始 DH 输出不应直接用作加密密钥，需要通过 KDF 处理：")
    print("  1. 增加随机性（混入 salt）")
    print("  2. 生成指定长度的密钥")
    print("  3. 可以派生多个不同用途的密钥")
    print()

    # 使用 HKDF 派生密钥 (WireGuard 使用类似机制)
    # HKDF = Extract + Expand
    salt = os.urandom(32)

    # 派生加密密钥
    encryption_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # ChaCha20 需要 256-bit 密钥
        salt=salt,
        info=b'wireguard encryption key',
    ).derive(shared_secret)

    # 派生认证密钥
    auth_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'wireguard authentication key',
    ).derive(shared_secret)

    print(f"  共享密钥:   {shared_secret.hex()[:32]}...")
    print(f"  Salt:       {salt.hex()[:32]}...")
    print(f"  加密密钥:   {encryption_key.hex()}")
    print(f"  认证密钥:   {auth_key.hex()}")
    print()
    print(f"  [关键] 相同的 shared_secret + salt + info → 相同的派生密钥")
    print(f"  [关键] 不同的 info → 不同的密钥 (密钥隔离)")

    return encryption_key


def demo_aead_encryption(key: bytes):
    """演示 AEAD 加密 (ChaCha20-Poly1305)"""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import struct

    print()
    print("=" * 70)
    print("AEAD 加密 (ChaCha20-Poly1305)")
    print("=" * 70)
    print()
    print("WireGuard 使用 ChaCha20-Poly1305 进行数据加密：")
    print("  - ChaCha20: 流密码，提供保密性")
    print("  - Poly1305: MAC，提供完整性和认证")
    print("  - AEAD: Authenticated Encryption with Associated Data")
    print()

    aead = ChaCha20Poly1305(key)

    # 模拟 WireGuard 的 counter 作为 nonce
    counter = 0

    # 模拟要加密的 IP 包
    plaintext = b'\x45\x00\x00\x3c' + b'\x00' * 56  # 模拟 60 字节 IP 包
    plaintext += b'Hello from VPN tunnel!'

    # Associated Data (不加密但需要认证的额外数据)
    # WireGuard 中 AD 为空，这里演示用
    associated_data = b''

    # Nonce: WireGuard 使用 64-bit counter + 32-bit 零填充
    nonce = struct.pack('<I', 0) + struct.pack('<Q', counter)  # 12 bytes

    print(f"  明文长度:     {len(plaintext)} bytes")
    print(f"  明文(前20B):  {plaintext[:20].hex()}")
    print(f"  Nonce:        {nonce.hex()} (counter={counter})")
    print()

    # 加密
    ciphertext = aead.encrypt(nonce, plaintext, associated_data)
    print(f"  密文长度:     {len(ciphertext)} bytes (+16B auth tag)")
    print(f"  密文(前20B):  {ciphertext[:20].hex()}")
    print(f"  Auth Tag:     {ciphertext[-16:].hex()}")
    print()

    # 解密
    decrypted = aead.decrypt(nonce, ciphertext, associated_data)
    assert decrypted == plaintext
    print(f"  解密验证:     ✓ (明文匹配)")
    print()

    # 演示篡改检测
    print("[安全演示] 篡改检测:")
    tampered = bytearray(ciphertext)
    tampered[10] ^= 0xFF  # 翻转一个字节
    try:
        aead.decrypt(nonce, bytes(tampered), associated_data)
        print("  ✗ 未检测到篡改！")
    except Exception:
        print("  ✓ 检测到篡改！解密失败 (Poly1305 MAC 验证不通过)")

    print()
    print("  [关键] AEAD 确保：")
    print("    1. 攻击者无法读取密文内容 (保密性)")
    print("    2. 攻击者无法修改密文 (完整性)")
    print("    3. 攻击者无法伪造消息 (认证)")
    print("    4. Nonce 必须唯一，否则安全性崩塌")


def demo_noise_protocol_overview():
    """Noise 协议框架概述"""
    print()
    print("=" * 70)
    print("Noise IK 协议 (WireGuard 使用的握手协议)")
    print("=" * 70)
    print()
    print("Noise 是一个密码学协议框架，WireGuard 使用 Noise_IKpsk2:")
    print()
    print("  'I' = Initiator 预先知道 Responder 的静态公钥")
    print("  'K' = Responder 预先知道 Initiator 的静态公钥")
    print("  'psk2' = 在第二条消息后混入预共享密钥")
    print()
    print("握手过程 (3 条消息):")
    print()
    print("  ┌─────── Initiator ───────────────── Responder ────────┐")
    print("  │                                                       │")
    print("  │  1. → e, es, s, ss                                   │")
    print("  │     (临时公钥, DH(e,S_r), 加密的静态公钥, DH(S_i,S_r))│")
    print("  │                                                       │")
    print("  │  2. ← e, ee, se, psk                                 │")
    print("  │     (临时公钥, DH(E_i,E_r), DH(S_i,E_r), PSK混入)    │")
    print("  │                                                       │")
    print("  │  [此时双方有了传输密钥]                                │")
    print("  │                                                       │")
    print("  │  3. → encrypted_data (使用传输密钥)                   │")
    print("  │                                                       │")
    print("  └───────────────────────────────────────────────────────┘")
    print()
    print("安全属性:")
    print("  - 前向保密: 长期密钥泄露不影响过去的通信")
    print("  - 身份隐藏: Initiator 的身份对被动监听者隐藏")
    print("  - 抗重放: 时间戳 + 递增 counter")
    print("  - 抗 DoS: Cookie 机制")


def main():
    shared_secret = demo_basic_key_exchange()
    key = demo_key_derivation(shared_secret)
    demo_aead_encryption(key)
    demo_noise_protocol_overview()

    print()
    print("=" * 70)
    print("总结:")
    print("  1. ECDH (Curve25519) 在不安全信道上协商共享密钥")
    print("  2. HKDF 从共享密钥派生多个加密/认证密钥")
    print("  3. ChaCha20-Poly1305 (AEAD) 同时提供加密和认证")
    print("  4. Noise IK 协议将以上原语组合为安全的握手流程")
    print("  5. 这些就是 WireGuard VPN 的密码学基础")
    print("=" * 70)


if __name__ == '__main__':
    main()
