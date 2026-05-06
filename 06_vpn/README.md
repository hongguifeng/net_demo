# 第六章：VPN 实现 (WireGuard 原理)

## 原理

VPN (Virtual Private Network) 本质是 **加密隧道**。与前一章的 IPIP/GRE 隧道相比，VPN 增加了：
- 数据加密 (保密性)
- 数据认证 (完整性)
- 密钥交换 (身份验证)
- 防重放攻击

### VPN 协议演进

| 协议 | 年代 | 特点 |
|------|------|------|
| PPTP | 1999 | 基于 GRE，已不安全 |
| IPsec | 1995+ | 复杂但功能全面 |
| OpenVPN | 2001 | 基于 TLS，用户态实现 |
| WireGuard | 2018 | 简洁，现代密码学，内核态 |

### WireGuard 设计哲学

WireGuard 代码仅 4000 行 (对比 OpenVPN 约 10万行)，核心设计：

1. **简洁的密码学选择** (无协商，固定使用):
   - Curve25519: ECDH 密钥交换
   - ChaCha20-Poly1305: AEAD 加密认证
   - BLAKE2s: 哈希
   - SipHash24: 哈希表键

2. **Cryptokey Routing**:
   每个 peer 有一个公钥和一组允许的 IP 范围。
   路由决策基于密钥而非传统路由表。

3. **静默性**:
   不响应未认证的包，对扫描者不可见。

### WireGuard 握手 (Noise IK 协议)

```
Initiator (i)                          Responder (r)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
已知: S_pub_r (对方公钥)               已知: S_pub_i (对方公钥)

1. Handshake Initiation:
   i → r: (sender, unencrypted_ephemeral, encrypted_static, encrypted_timestamp)
   
   - 生成临时密钥对 E_i
   - 用 E_i + S_pub_r 做 DH，派生密钥
   - 用派生密钥加密自己的公钥 S_pub_i
   - 用派生密钥加密时间戳 (防重放)

2. Handshake Response:
   r → i: (sender, receiver, unencrypted_ephemeral, encrypted_nothing)
   
   - 生成临时密钥对 E_r
   - 用 E_r + E_i, E_r + S_pub_i 做 DH
   - 派生传输密钥

3. 之后的数据传输使用协商好的对称密钥加密
```

### 数据包格式

```
WireGuard 消息类型:
  Type 1: Handshake Initiation (148 bytes)
  Type 2: Handshake Response (92 bytes)
  Type 3: Cookie Reply (64 bytes)
  Type 4: Transport Data (variable)

Transport Data:
┌──────────┬──────────────┬─────────────────────────────────────┬──────────┐
│ Type (1) │ Reserved (3) │ Receiver Index (4) │ Counter (8)     │ Encrypted│
│  = 4     │              │                    │ (nonce)         │ IP Packet│
└──────────┴──────────────┴─────────────────────────────────────┴──────────┘
```

### MTU 考虑

```
原始 MTU (以太网): 1500
- IPv4 外部头:      -20
- UDP 头:           -8
- WireGuard 头:     -32 (type+reserved+receiver+counter+auth_tag)
= 内部 MTU:         1440

所以 WireGuard 接口 MTU 通常设为 1420
```

## 示例代码

| 文件 | 说明 |
|------|------|
| `simple_vpn.py` | 简化版 VPN 实现 (TUN + 加密隧道) |
| `wireguard_lite.py` | WireGuard 协议精简实现 (握手+传输) |
| `key_exchange.py` | Curve25519 密钥交换演示 |

## 运行

```bash
pip3 install cryptography
sudo python3 key_exchange.py          # 无需 root
sudo python3 simple_vpn.py server     # 终端1
sudo python3 simple_vpn.py client     # 终端2
sudo python3 wireguard_lite.py        # 自动演示
```
