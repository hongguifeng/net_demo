# 网络协议栈实战教程

## 目标读者
对 TCP/IP 有基本了解的软件开发工程师，希望深入理解网络协议栈各层原理并通过代码实践掌握隧道、VPN 等上层网络技术。

## 环境要求
- Linux (Ubuntu 20.04+ 推荐)
- Python 3.8+
- GCC / Make
- root 权限 (部分实验需要)

```bash
# 安装依赖
sudo apt-get install -y python3-pip python3-dev iproute2 tcpdump wireshark-common
pip3 install scapy cryptography
```

## 教程结构

| 章节 | 主题 | 目录 |
|------|------|------|
| 01 | 以太网帧解析与构造 | [01_ethernet/](01_ethernet/) |
| 02 | IP 数据包构造与路由 | [02_ip/](02_ip/) |
| 03 | TCP/UDP 原始套接字 | [03_transport/](03_transport/) |
| 04 | TUN/TAP 虚拟网络接口 | [04_tun_tap/](04_tun_tap/) |
| 05 | IP 隧道 (IPIP/GRE) | [05_tunnel/](05_tunnel/) |
| 06 | VPN 实现 (WireGuard 原理) | [06_vpn/](06_vpn/) |
| 07 | SOCKS5 代理协议 | [07_socks5/](07_socks5/) |
| 08 | HTTP 隧道与 CONNECT | [08_http_tunnel/](08_http_tunnel/) |
| 09 | DNS 协议实现 | [09_dns/](09_dns/) |

## 学习路径

```
┌─────────────┐
│  L2 以太网   │ ← 理解帧格式、MAC 地址
├─────────────┤
│  L3 IP 层    │ ← 包构造、分片、路由
├─────────────┤
│  L4 传输层   │ ← TCP 状态机、UDP
├─────────────┤
│  TUN/TAP    │ ← 虚拟网卡、用户态网络
├─────────────┤
│  隧道协议    │ ← IPIP、GRE、封装原理
├─────────────┤
│  VPN        │ ← 加密隧道、密钥交换
├─────────────┤
│  应用层代理  │ ← SOCKS5、HTTP CONNECT
├─────────────┤
│  DNS        │ ← 域名解析协议实现
└─────────────┘
```

## 运行说明
每个章节目录下都有独立的 `README.md` 说明文件和可执行代码。
部分实验需要 root 权限，请在安全的测试环境中运行。

## 统一验证

项目根目录提供自动化验证脚本 [verify_all.py](verify_all.py)，用于检查示例代码可执行性与核心逻辑正确性。

```bash
# 1) 快速模式: 语法 + 本地单元测试（默认推荐）
python3 verify_all.py --quick

# 2) 完整模式: quick + 集成测试（本地进程 + 外网 DNS）
python3 verify_all.py --full

# 3) root 模式: full + 强制 root 相关测试
sudo python3 verify_all.py --root
```

说明：
- `--quick` 适合日常快速回归，不依赖 root 和外网。
- `--full` 会尝试运行 SOCKS5/DNS 集成测试，外网不可用时会显示 `SKIP`。
- `--root` 要求 root 权限，否则脚本会直接报错退出。
