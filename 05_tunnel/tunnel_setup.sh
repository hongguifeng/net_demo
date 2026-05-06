#!/bin/bash
# 内核态隧道快速配置脚本
#
# 使用 network namespace 模拟两个站点间的隧道
# 这是生产环境中配置隧道的标准方法
#
# 拓扑:
#   ns1 (10.0.0.1) ←veth→ ns2 (10.0.0.2)
#   隧道内网: ns1 (192.168.1.1) ←隧道→ ns2 (192.168.1.2)

set -e

echo "========================================"
echo "内核态隧道配置演示"
echo "========================================"
echo

# 清理可能存在的旧配置
cleanup() {
    ip netns del ns1 2>/dev/null || true
    ip netns del ns2 2>/dev/null || true
    echo "[✓] 清理完成"
}

trap cleanup EXIT

# 创建 network namespace
echo "[1] 创建 Network Namespaces"
ip netns add ns1
ip netns add ns2
echo "    ns1, ns2 创建完成"

# 创建 veth pair 连接两个 namespace
echo "[2] 创建 veth pair"
ip link add veth1 type veth peer name veth2
ip link set veth1 netns ns1
ip link set veth2 netns ns2
echo "    veth1 → ns1, veth2 → ns2"

# 配置 IP 地址
echo "[3] 配置底层 IP (模拟公网连接)"
ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec ns1 ip link set veth1 up
ip netns exec ns1 ip link set lo up

ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
ip netns exec ns2 ip link set veth2 up
ip netns exec ns2 ip link set lo up
echo "    ns1: 10.0.0.1/24, ns2: 10.0.0.2/24"

# 验证底层连通性
echo "[4] 验证底层连通性"
ip netns exec ns1 ping -c 1 -W 1 10.0.0.2 > /dev/null && echo "    ns1 → ns2: ✓" || echo "    ns1 → ns2: ✗"

echo
echo "════════════════════════════════════════"
echo "  IPIP 隧道配置"
echo "════════════════════════════════════════"

# 配置 IPIP 隧道
echo "[5] 创建 IPIP 隧道"
ip netns exec ns1 ip tunnel add ipip0 mode ipip local 10.0.0.1 remote 10.0.0.2
ip netns exec ns1 ip addr add 192.168.1.1/24 dev ipip0
ip netns exec ns1 ip link set ipip0 up

ip netns exec ns2 ip tunnel add ipip0 mode ipip local 10.0.0.2 remote 10.0.0.1
ip netns exec ns2 ip addr add 192.168.1.2/24 dev ipip0
ip netns exec ns2 ip link set ipip0 up
echo "    ns1 ipip0: 192.168.1.1/24"
echo "    ns2 ipip0: 192.168.1.2/24"

# 测试 IPIP 隧道
echo "[6] 测试 IPIP 隧道"
ip netns exec ns1 ping -c 3 -W 1 192.168.1.2
echo "    IPIP 隧道: ✓"

# 查看隧道信息
echo "[7] IPIP 隧道信息"
echo "    ns1:"
ip netns exec ns1 ip tunnel show
echo "    ns2:"
ip netns exec ns2 ip tunnel show

# 清理 IPIP
ip netns exec ns1 ip tunnel del ipip0
ip netns exec ns2 ip tunnel del ipip0

echo
echo "════════════════════════════════════════"
echo "  GRE 隧道配置"
echo "════════════════════════════════════════"

# 配置 GRE 隧道 (带 Key)
echo "[8] 创建 GRE 隧道 (Key=1001)"
ip netns exec ns1 ip tunnel add gre1 mode gre local 10.0.0.1 remote 10.0.0.2 key 1001
ip netns exec ns1 ip addr add 172.16.0.1/24 dev gre1
ip netns exec ns1 ip link set gre1 up

ip netns exec ns2 ip tunnel add gre1 mode gre local 10.0.0.2 remote 10.0.0.1 key 1001
ip netns exec ns2 ip addr add 172.16.0.2/24 dev gre1
ip netns exec ns2 ip link set gre1 up
echo "    ns1 gre1: 172.16.0.1/24 (key=1001)"
echo "    ns2 gre1: 172.16.0.2/24 (key=1001)"

# 测试 GRE 隧道
echo "[9] 测试 GRE 隧道"
ip netns exec ns1 ping -c 3 -W 1 172.16.0.2
echo "    GRE 隧道: ✓"

# 抓包查看 GRE 封装
echo "[10] 抓包验证 GRE 封装"
ip netns exec ns2 tcpdump -i veth2 -c 2 -n proto gre &
TCPDUMP_PID=$!
sleep 0.5
ip netns exec ns1 ping -c 2 -W 1 172.16.0.2 > /dev/null
wait $TCPDUMP_PID 2>/dev/null || true

echo
echo "========================================"
echo "总结:"
echo "  IPIP: 最简单，仅 20B 开销，仅支持 IPv4-in-IPv4"
echo "  GRE:  灵活，支持 Key/多协议，4-16B GRE 头开销"
echo "  两者都不加密！生产环境需配合 IPsec 使用"
echo "========================================"
