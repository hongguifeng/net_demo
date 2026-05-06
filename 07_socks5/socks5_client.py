#!/usr/bin/env python3
"""
SOCKS5 客户端库和测试

原理：
  SOCKS5 客户端需要按照协议格式与代理服务器通信：
  1. 发送认证方法列表
  2. 完成认证
  3. 发送连接请求 (目标地址+端口)
  4. 确认连接成功后，正常收发数据

  这让我们理解客户端如何使用 SOCKS5 代理。

运行方式：
  # 先启动代理服务器
  python3 socks5_server.py

  # 然后运行客户端测试
  python3 socks5_client.py

验证方法：
  观察是否能通过代理成功访问目标服务
"""

import socket
import struct
import sys


class SOCKS5Client:
    """
    SOCKS5 客户端

    使用方法:
        client = SOCKS5Client('127.0.0.1', 1080)
        client.connect('example.com', 80)
        client.send(b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n')
        response = client.recv(4096)
        client.close()
    """

    def __init__(self, proxy_host: str, proxy_port: int,
                 username: str = None, password: str = None):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        self.sock = None

    def connect(self, dst_host: str, dst_port: int):
        """通过 SOCKS5 代理连接到目标"""
        # 连接到代理服务器
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.proxy_host, self.proxy_port))

        # 步骤 1: 认证协商
        self._negotiate_auth()

        # 步骤 2: 发送连接请求
        self._send_connect(dst_host, dst_port)

    def _negotiate_auth(self):
        """协商认证方法"""
        if self.username:
            # 支持无认证和用户名密码
            self.sock.send(struct.pack('!BBB', 5, 2, 0) + b'\x02')
        else:
            # 仅无认证
            self.sock.send(struct.pack('!BBB', 5, 1, 0))

        # 读取服务端选择的方法
        response = self.sock.recv(2)
        version, method = struct.unpack('!BB', response)

        if version != 5:
            raise Exception(f"代理返回错误版本: {version}")

        if method == 0xFF:
            raise Exception("代理拒绝所有认证方法")

        if method == 0x02:
            self._auth_password()

    def _auth_password(self):
        """用户名密码认证"""
        if not self.username or not self.password:
            raise Exception("需要用户名密码认证")

        # 发送认证信息
        uname = self.username.encode()
        passwd = self.password.encode()
        auth_msg = struct.pack('!BB', 1, len(uname)) + uname
        auth_msg += struct.pack('!B', len(passwd)) + passwd
        self.sock.send(auth_msg)

        # 读取认证结果
        response = self.sock.recv(2)
        if response[1] != 0:
            raise Exception("认证失败")

    def _send_connect(self, dst_host: str, dst_port: int):
        """发送 CONNECT 请求"""
        # 判断地址类型
        try:
            # 尝试作为 IPv4 解析
            addr_bytes = socket.inet_aton(dst_host)
            atyp = 0x01
            addr_data = addr_bytes
        except OSError:
            # 作为域名处理
            atyp = 0x03
            domain = dst_host.encode()
            addr_data = struct.pack('!B', len(domain)) + domain

        # 构造请求
        request = struct.pack('!BBBB', 5, 1, 0, atyp)
        request += addr_data
        request += struct.pack('!H', dst_port)
        self.sock.send(request)

        # 读取响应
        response = self.sock.recv(4)
        version, rep, _, atyp = struct.unpack('!BBBB', response)

        # 读取绑定地址 (根据地址类型)
        if atyp == 0x01:
            self.sock.recv(4)  # IPv4
        elif atyp == 0x03:
            domain_len = self.sock.recv(1)[0]
            self.sock.recv(domain_len)
        elif atyp == 0x04:
            self.sock.recv(16)  # IPv6

        self.sock.recv(2)  # 端口

        if rep != 0:
            error_msgs = {
                1: '一般性失败', 2: '规则不允许',
                3: '网络不可达', 4: '主机不可达',
                5: '连接被拒绝', 6: 'TTL 过期',
                7: '命令不支持', 8: '地址类型不支持'
            }
            raise Exception(f"连接失败: {error_msgs.get(rep, f'未知错误({rep})')}")

    def send(self, data: bytes):
        """发送数据"""
        self.sock.sendall(data)

    def recv(self, bufsize: int) -> bytes:
        """接收数据"""
        return self.sock.recv(bufsize)

    def close(self):
        """关闭连接"""
        if self.sock:
            self.sock.close()


def test_http_via_socks5(proxy_host: str = '127.0.0.1', proxy_port: int = 1080):
    """通过 SOCKS5 代理发送 HTTP 请求"""
    print("=" * 60)
    print("SOCKS5 客户端测试")
    print("=" * 60)
    print()

    # 测试 1: 连接到本地 HTTP 服务
    print("[测试 1] 通过 SOCKS5 代理连接到 httpbin.org")
    print(f"  代理: {proxy_host}:{proxy_port}")
    print(f"  目标: httpbin.org:80")
    print()

    try:
        client = SOCKS5Client(proxy_host, proxy_port)
        client.connect('httpbin.org', 80)

        # 发送 HTTP 请求
        request = (
            b'GET /ip HTTP/1.1\r\n'
            b'Host: httpbin.org\r\n'
            b'Connection: close\r\n'
            b'\r\n'
        )
        client.send(request)

        # 接收响应
        response = b''
        while True:
            data = client.recv(4096)
            if not data:
                break
            response += data

        client.close()

        # 显示结果
        response_str = response.decode('utf-8', errors='replace')
        lines = response_str.split('\r\n')
        print(f"  状态: {lines[0]}")
        print(f"  响应长度: {len(response)} bytes")

        # 找到 body
        body_start = response_str.find('\r\n\r\n')
        if body_start >= 0:
            body = response_str[body_start + 4:]
            print(f"  Body: {body.strip()[:200]}")

        print(f"  [✓] 成功通过 SOCKS5 代理访问")

    except ConnectionRefusedError:
        print(f"  [!] 无法连接到代理 {proxy_host}:{proxy_port}")
        print(f"      请先启动代理: python3 socks5_server.py")
    except Exception as e:
        print(f"  [!] 错误: {e}")

    print()

    # 测试 2: 域名解析 (SOCKS5 支持代理端解析域名)
    print("[测试 2] 域名解析测试")
    print("  SOCKS5 ATYP=0x03 (域名) 让代理服务器负责 DNS 解析")
    print("  这避免了 DNS 泄露 (本地不需要解析域名)")
    print()

    # 测试 3: 连接本地服务
    print("[测试 3] 通过 SOCKS5 代理连接本地服务")

    # 先启动一个简单的测试服务器
    import threading
    test_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    test_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    test_server.bind(('127.0.0.1', 8899))
    test_server.listen(1)

    def echo_handler():
        conn, _ = test_server.accept()
        data = conn.recv(1024)
        conn.sendall(b'ECHO: ' + data)
        conn.close()
        test_server.close()

    thread = threading.Thread(target=echo_handler, daemon=True)
    thread.start()

    import time
    time.sleep(0.2)

    try:
        client = SOCKS5Client(proxy_host, proxy_port)
        client.connect('127.0.0.1', 8899)
        client.send(b'Hello via SOCKS5!')
        response = client.recv(1024)
        client.close()

        print(f"  发送: 'Hello via SOCKS5!'")
        print(f"  收到: '{response.decode()}'")
        expected = b'ECHO: Hello via SOCKS5!'
        print(f"  验证: {'✓' if response == expected else '✗'}")

    except ConnectionRefusedError:
        print(f"  [!] 无法连接到代理，跳过")
    except Exception as e:
        print(f"  [!] 错误: {e}")

    print()
    print("=" * 60)
    print("SOCKS5 协议要点:")
    print("  1. 通用代理: 支持任意 TCP 流量")
    print("  2. 域名代理: 避免本地 DNS 泄露")
    print("  3. 应用广泛: SSH -D, tor, shadowsocks 都基于 SOCKS5")
    print("  4. 简单高效: 握手后就是纯数据转发，零额外开销")
    print("=" * 60)


if __name__ == '__main__':
    proxy_host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    proxy_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
    test_http_via_socks5(proxy_host, proxy_port)
