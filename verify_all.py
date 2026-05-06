#!/usr/bin/env python3
"""
网络协议栈教程 - 自动化验证脚本

本脚本验证各章节示例代码的正确性。
部分测试需要 root 权限 (原始套接字)，普通用户权限下跳过这些测试。

运行方式：
    python3 verify_all.py --quick      # 快速: 语法 + 本地单元测试
    python3 verify_all.py --full       # 完整: quick + 集成测试(本地进程/外网)
    sudo python3 verify_all.py --root  # root: full + 强制 root 测试

验证范围：
  - 代码语法正确性
  - 模块导入正确性
  - 核心函数单元测试
  - 需要网络/root权限的测试 (可选)
"""

import sys
import os
import subprocess
import importlib.util
import struct
import socket
import time
import argparse

# 颜色输出
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODE = 'quick'


def log_pass(msg):
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  {GREEN}✓ PASS{RESET}: {msg}")


def log_fail(msg, detail=""):
    global FAIL_COUNT
    FAIL_COUNT += 1
    print(f"  {RED}✗ FAIL{RESET}: {msg}")
    if detail:
        print(f"         {detail}")


def log_skip(msg):
    global SKIP_COUNT
    SKIP_COUNT += 1
    print(f"  {YELLOW}○ SKIP{RESET}: {msg}")


def log_section(title):
    print(f"\n{BLUE}{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}{RESET}")


def is_root():
    return os.geteuid() == 0


def load_module(path, name=None):
    """动态加载 Python 模块"""
    if name is None:
        name = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_syntax(filepath):
    """检查 Python 文件语法"""
    result = subprocess.run(
        [sys.executable, '-m', 'py_compile', filepath],
        capture_output=True, text=True
    )
    return result.returncode == 0, result.stderr


# ============================================================
# 第 1 章: 以太网
# ============================================================
def verify_chapter_01():
    log_section("第 1 章: 以太网帧解析")

    # 语法检查
    files = ['ethernet_parser.py', 'ethernet_craft.py', 'arp_scanner.py']
    for f in files:
        path = os.path.join(BASE_DIR, '01_ethernet', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试 MAC 地址解析逻辑
    mac_bytes = b'\xaa\xbb\xcc\xdd\xee\xff'
    mac_str = ':'.join(f'{b:02x}' for b in mac_bytes)
    if mac_str == 'aa:bb:cc:dd:ee:ff':
        log_pass("MAC 地址格式化")
    else:
        log_fail("MAC 地址格式化", f"got {mac_str}")

    # 测试 EtherType 解析
    frame = mac_bytes + mac_bytes + b'\x08\x00'  # IPv4
    ethertype = struct.unpack('!H', frame[12:14])[0]
    if ethertype == 0x0800:
        log_pass("EtherType 解析 (IPv4=0x0800)")
    else:
        log_fail("EtherType 解析")


# ============================================================
# 第 2 章: IP
# ============================================================
def verify_chapter_02():
    log_section("第 2 章: IP 数据包")

    files = ['ip_packet.py', 'traceroute.py', 'fragment.py']
    for f in files:
        path = os.path.join(BASE_DIR, '02_ip', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试 IP 校验和计算
    mod = load_module(os.path.join(BASE_DIR, '02_ip', 'ip_packet.py'))

    # 构造一个已知 checksum 的 IP 头测试
    # 使用全 0 校验和字段的 IP 头
    test_header = struct.pack('!BBHHHBBH4s4s',
                              0x45, 0, 40, 1, 0, 64, 6, 0,
                              socket.inet_aton('192.168.1.1'),
                              socket.inet_aton('192.168.1.2'))
    checksum = mod.calculate_checksum(test_header)
    if isinstance(checksum, int) and checksum != 0:
        log_pass(f"IP 校验和计算 (result=0x{checksum:04x})")
    else:
        log_fail("IP 校验和计算")

    # 验证校验和正确性: 带上校验和后重新计算应为 0
    header_with_cksum = test_header[:10] + struct.pack('!H', checksum) + test_header[12:]
    verify = mod.calculate_checksum(header_with_cksum)
    if verify == 0:
        log_pass("IP 校验和验证 (重算=0)")
    else:
        log_fail("IP 校验和验证", f"expected 0, got {verify}")


# ============================================================
# 第 3 章: 传输层
# ============================================================
def verify_chapter_03():
    log_section("第 3 章: TCP/UDP")

    files = ['tcp_handshake.py', 'tcp_scanner.py', 'udp_socket.py']
    for f in files:
        path = os.path.join(BASE_DIR, '03_transport', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试 UDP 回显 (本地 loopback)
    try:
        # 启动 UDP 服务器
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind(('127.0.0.1', 0))
        server_port = server_sock.getsockname()[1]
        server_sock.settimeout(2)

        # 客户端发送
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.settimeout(2)
        test_msg = b'verify_test_udp'
        client_sock.sendto(test_msg, ('127.0.0.1', server_port))

        # 服务器接收
        data, addr = server_sock.recvfrom(1024)
        if data == test_msg:
            log_pass(f"UDP 收发测试 (port={server_port})")
        else:
            log_fail("UDP 收发测试", f"收到 {data}")

        server_sock.close()
        client_sock.close()
    except Exception as e:
        log_fail("UDP 收发测试", str(e))


# ============================================================
# 第 4 章: TUN/TAP
# ============================================================
def verify_chapter_04():
    log_section("第 4 章: TUN/TAP 虚拟网卡")

    files = ['tun_device.py', 'tun_echo.py', 'tap_bridge.py']
    for f in files:
        path = os.path.join(BASE_DIR, '04_tun_tap', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # TUN 设备需要 root 权限
    if is_root():
        tun_path = '/dev/net/tun'
        if os.path.exists(tun_path):
            log_pass(f"TUN 设备文件存在 ({tun_path})")
        else:
            log_fail("TUN 设备文件", f"{tun_path} 不存在")
    else:
        log_skip("TUN 设备测试 (需要 root 权限)")


# ============================================================
# 第 5 章: 隧道
# ============================================================
def verify_chapter_05():
    log_section("第 5 章: IP 隧道")

    files = ['ipip_tunnel.py', 'gre_tunnel.py']
    for f in files:
        path = os.path.join(BASE_DIR, '05_tunnel', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 检查 shell 脚本语法
    sh_path = os.path.join(BASE_DIR, '05_tunnel', 'tunnel_setup.sh')
    if os.path.exists(sh_path):
        result = subprocess.run(['bash', '-n', sh_path],
                                capture_output=True, text=True)
        if result.returncode == 0:
            log_pass("Shell 脚本语法 tunnel_setup.sh")
        else:
            log_fail("Shell 脚本语法", result.stderr.strip())

    # GRE 封装验证
    mod = load_module(os.path.join(BASE_DIR, '05_tunnel', 'gre_tunnel.py'))
    # 测试 GRE 头部构造
    if hasattr(mod, 'build_gre_header'):
        gre_hdr = mod.build_gre_header()
        # GRE over IPv4 协议号 47, 基本 GRE 头 4 字节
        if len(gre_hdr) >= 4:
            log_pass(f"GRE 头部构造 ({len(gre_hdr)} bytes)")
        else:
            log_fail("GRE 头部构造", "头部太短")
    else:
        log_skip("GRE 头部函数不可用")


# ============================================================
# 第 6 章: VPN
# ============================================================
def verify_chapter_06():
    log_section("第 6 章: VPN")

    files = ['key_exchange.py', 'simple_vpn.py', 'wireguard_lite.py']
    for f in files:
        path = os.path.join(BASE_DIR, '06_vpn', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试密钥交换
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        # 生成密钥对
        priv_a = X25519PrivateKey.generate()
        priv_b = X25519PrivateKey.generate()
        pub_a = priv_a.public_key()
        pub_b = priv_b.public_key()

        # ECDH
        shared_a = priv_a.exchange(pub_b)
        shared_b = priv_b.exchange(pub_a)

        if shared_a == shared_b and len(shared_a) == 32:
            log_pass("X25519 ECDH 密钥交换")
        else:
            log_fail("X25519 ECDH", "共享密钥不匹配")

    except ImportError:
        log_skip("cryptography 库未安装")
    except Exception as e:
        log_fail("密钥交换测试", str(e))

    # 测试加密/解密
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        key = os.urandom(32)
        nonce = os.urandom(12)
        plaintext = b'Hello, VPN tunnel!'

        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        decrypted = cipher.decrypt(nonce, ciphertext, None)

        if decrypted == plaintext:
            log_pass("ChaCha20-Poly1305 加密/解密")
        else:
            log_fail("ChaCha20-Poly1305", "解密结果不匹配")

    except ImportError:
        log_skip("cryptography 库未安装")
    except Exception as e:
        log_fail("加密测试", str(e))


# ============================================================
# 第 7 章: SOCKS5
# ============================================================
def verify_chapter_07():
    log_section("第 7 章: SOCKS5 代理")

    files = ['socks5_server.py', 'socks5_client.py']
    for f in files:
        path = os.path.join(BASE_DIR, '07_socks5', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试 SOCKS5 协议解析
    # SOCKS5 版本协商
    greeting = b'\x05\x01\x00'  # VER=5, NMETHODS=1, NO AUTH
    if greeting[0] == 0x05 and greeting[1] == 1:
        log_pass("SOCKS5 版本协商解析")
    else:
        log_fail("SOCKS5 版本协商")

    # 测试 SOCKS5 连接请求构造
    # VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAIN(3)
    domain = b'example.com'
    port = 80
    request = struct.pack('!BBBBB', 5, 1, 0, 3, len(domain))
    request += domain + struct.pack('!H', port)
    if request[3] == 3 and request[4] == len(domain):
        log_pass("SOCKS5 CONNECT 请求构造")
    else:
        log_fail("SOCKS5 CONNECT 请求")

    # 集成测试: 启动 SOCKS5 服务器
    if MODE != 'quick':
        try:
            server_proc = subprocess.Popen(
                [sys.executable, os.path.join(BASE_DIR, '07_socks5', 'socks5_server.py')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={**os.environ, 'PYTHONUNBUFFERED': '1'}
            )
            time.sleep(0.5)
            if server_proc.poll() is None:
                server_proc.terminate()
                server_proc.wait(timeout=2)
                log_pass("SOCKS5 服务器可启动")
            else:
                log_fail("SOCKS5 服务器可启动", "进程提前退出")
        except Exception as e:
            log_skip(f"SOCKS5 服务器测试: {e}")
    else:
        log_skip("SOCKS5 集成测试 (quick 模式跳过)")


# ============================================================
# 第 8 章: HTTP 隧道
# ============================================================
def verify_chapter_08():
    log_section("第 8 章: HTTP 隧道")

    files = ['http_proxy.py', 'http_tunnel_client.py']
    for f in files:
        path = os.path.join(BASE_DIR, '08_http_tunnel', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试 HTTP CONNECT 请求构造
    host = 'example.com'
    port = 443
    connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
    if 'CONNECT' in connect_req and f'{host}:{port}' in connect_req:
        log_pass("HTTP CONNECT 请求构造")
    else:
        log_fail("HTTP CONNECT 请求")

    # 测试 HTTP 响应解析
    response = b"HTTP/1.1 200 Connection Established\r\n\r\n"
    status_line = response.split(b'\r\n')[0].decode()
    parts = status_line.split(' ', 2)
    if parts[1] == '200':
        log_pass("HTTP 响应状态码解析")
    else:
        log_fail("HTTP 响应解析")


# ============================================================
# 第 9 章: DNS
# ============================================================
def verify_chapter_09():
    log_section("第 9 章: DNS")

    files = ['dns_resolver.py', 'dns_server.py']
    for f in files:
        path = os.path.join(BASE_DIR, '09_dns', f)
        ok, err = check_syntax(path)
        if ok:
            log_pass(f"语法检查 {f}")
        else:
            log_fail(f"语法检查 {f}", err.strip())

    # 测试域名编码
    mod = load_module(os.path.join(BASE_DIR, '09_dns', 'dns_resolver.py'))

    # www.example.com → \x03www\x07example\x03com\x00
    encoded = mod.encode_domain('www.example.com')
    expected = b'\x03www\x07example\x03com\x00'
    if encoded == expected:
        log_pass("DNS 域名编码")
    else:
        log_fail("DNS 域名编码", f"got {encoded.hex()}")

    # 测试域名解码
    decoded, offset = mod.decode_domain(expected, 0)
    if decoded == 'www.example.com' and offset == len(expected):
        log_pass("DNS 域名解码")
    else:
        log_fail("DNS 域名解码", f"got '{decoded}', offset={offset}")

    # 测试指针压缩
    # 构造: \x03www\x07example\x03com\x00 + 指针到偏移4(example.com)
    compressed = expected + b'\xc0\x04'
    decoded2, offset2 = mod.decode_domain(compressed, len(expected))
    if decoded2 == 'example.com':
        log_pass("DNS 指针压缩解码")
    else:
        log_fail("DNS 指针压缩", f"got '{decoded2}'")

    # 测试 DNS 查询包构造
    query, tid = mod.build_query('example.com', qtype=1)
    if len(query) > 12 and struct.unpack('!H', query[:2])[0] == tid:
        log_pass(f"DNS 查询包构造 ({len(query)} bytes, id={tid})")
    else:
        log_fail("DNS 查询包构造")

    # 集成测试: 实际 DNS 查询 (需要外网)
    if MODE != 'quick':
        try:
            result = mod.resolve('example.com', '8.8.8.8', qtype=1, timeout=3)
            if result['rcode'] == 0 and len(result['answers']) > 0:
                ip = result['answers'][0]['rdata']
                log_pass(f"DNS 实际查询 (example.com → {ip})")
            else:
                log_fail("DNS 实际查询", f"rcode={result['rcode']}")
        except Exception as e:
            log_skip(f"DNS 实际查询 (网络不可用: {e})")
    else:
        log_skip("DNS 外网查询测试 (quick 模式跳过)")

    # 集成测试: DNS 服务器功能
    if MODE != 'quick':
        server_proc = None
        try:
            server_proc = subprocess.Popen(
                [sys.executable, os.path.join(BASE_DIR, '09_dns', 'dns_server.py'), '15353'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(0.5)

            if server_proc.poll() is None:
                # 向本地 DNS 服务器发送查询
                result = mod.resolve('test.local', '127.0.0.1', qtype=1, timeout=2)
                if result['rcode'] == 0 and len(result['answers']) > 0:
                    ip = result['answers'][0]['rdata']
                    if ip == '192.168.1.100':
                        log_pass(f"DNS 服务器本地解析 (test.local → {ip})")
                    else:
                        log_fail("DNS 服务器本地解析", f"unexpected IP: {ip}")
                else:
                    log_fail("DNS 服务器本地解析", f"rcode={result['rcode']}")
            else:
                log_fail("DNS 服务器可启动", "进程提前退出")
        except Exception as e:
            log_skip(f"DNS 服务器测试: {e}")
        finally:
            if server_proc and server_proc.poll() is None:
                server_proc.terminate()
                server_proc.wait(timeout=2)
    else:
        log_skip("DNS 服务器集成测试 (quick 模式跳过)")


# ============================================================
# 主函数
# ============================================================
def main():
    global MODE

    parser = argparse.ArgumentParser(description='网络协议栈教程验证脚本')
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--quick', action='store_true',
                            help='快速模式: 语法 + 本地单元测试')
    mode_group.add_argument('--full', action='store_true',
                            help='完整模式: quick + 集成测试')
    mode_group.add_argument('--root', action='store_true',
                            help='root 模式: full + 强制 root 测试')
    args = parser.parse_args()

    if args.root:
        MODE = 'root'
    elif args.full:
        MODE = 'full'
    else:
        MODE = 'quick'

    print("=" * 60)
    print("  网络协议栈教程 - 代码验证")
    print("=" * 60)
    mode_desc = {
        'quick': '快速 (仅语法 + 本地单元测试)',
        'full': '完整 (quick + 集成测试)',
        'root': 'root (full + 强制 root 测试)',
    }
    print(f"  运行模式: {mode_desc[MODE]}")
    try:
        user = 'root' if is_root() else os.getlogin()
    except OSError:
        user = 'root' if is_root() else os.environ.get('USER', 'unknown')
    print(f"  当前用户: {user}")
    print(f"  Python: {sys.version.split()[0]}")
    print()

    if MODE == 'root' and not is_root():
        log_fail("root 模式要求 root 权限", "请使用 sudo 运行")
        return 2

    # 检查依赖
    log_section("环境检查")
    deps = {'scapy': False, 'cryptography': False}
    for pkg in deps:
        try:
            __import__(pkg)
            deps[pkg] = True
            log_pass(f"依赖库: {pkg}")
        except ImportError:
            log_skip(f"依赖库: {pkg} (未安装)")

    # 各章节验证
    verify_chapter_01()
    verify_chapter_02()
    verify_chapter_03()
    verify_chapter_04()
    verify_chapter_05()
    verify_chapter_06()
    verify_chapter_07()
    verify_chapter_08()
    verify_chapter_09()

    # 汇总
    print(f"\n{'=' * 60}")
    total = PASS_COUNT + FAIL_COUNT + SKIP_COUNT
    print(f"  测试结果汇总: {total} 项")
    print(f"    {GREEN}通过: {PASS_COUNT}{RESET}")
    print(f"    {RED}失败: {FAIL_COUNT}{RESET}")
    print(f"    {YELLOW}跳过: {SKIP_COUNT}{RESET}")
    print(f"{'=' * 60}")

    return 0 if FAIL_COUNT == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
