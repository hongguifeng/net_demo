#!/usr/bin/env python3
"""
HTTP 隧道客户端 - 演示通过 HTTP CONNECT 建立隧道

原理：
  通过 HTTP CONNECT 方法，可以在 HTTP 代理上建立 TCP 隧道。
  这是穿越防火墙最常用的技术之一。

  典型应用场景：
  - HTTPS 通过企业代理出网
  - SSH over HTTP (穿越只允许 HTTP 的网络)
  - 任意 TCP 协议通过 HTTP 代理传输

运行方式：
  # 先启动代理
  python3 http_proxy.py

  # 然后运行客户端
  python3 http_tunnel_client.py

验证方法：
  观察是否能通过 HTTP 代理建立 TCP 连接并传输数据
"""

import socket
import ssl
import sys
import threading
import time


def http_connect(proxy_host: str, proxy_port: int,
                 target_host: str, target_port: int,
                 auth: str = None) -> socket.socket:
    """
    通过 HTTP CONNECT 建立隧道

    参数:
        proxy_host/port: 代理地址
        target_host/port: 目标地址
        auth: HTTP Basic Auth (user:pass 的 base64)

    返回:
        已连接的 socket (隧道已建立，可以直接收发数据)
    """
    # 连接代理
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((proxy_host, proxy_port))

    # 发送 CONNECT 请求
    request = f'CONNECT {target_host}:{target_port} HTTP/1.1\r\n'
    request += f'Host: {target_host}:{target_port}\r\n'
    if auth:
        import base64
        encoded = base64.b64encode(auth.encode()).decode()
        request += f'Proxy-Authorization: Basic {encoded}\r\n'
    request += '\r\n'

    sock.sendall(request.encode())

    # 读取响应
    response = b''
    while b'\r\n\r\n' not in response:
        data = sock.recv(4096)
        if not data:
            raise Exception("代理连接断开")
        response += data

    # 解析状态码
    status_line = response.split(b'\r\n')[0].decode()
    parts = status_line.split(' ', 2)
    status_code = int(parts[1])

    if status_code != 200:
        raise Exception(f"CONNECT 失败: {status_line}")

    return sock


def test_https_via_connect():
    """测试通过 HTTP CONNECT 隧道访问 HTTPS"""
    print("[测试 1] HTTPS 通过 HTTP CONNECT 隧道")
    print("  场景: Client → HTTP Proxy → HTTPS Server")
    print()

    proxy_host = '127.0.0.1'
    proxy_port = 8080
    target_host = 'example.com'
    target_port = 443

    try:
        # 建立 CONNECT 隧道
        tunnel_sock = http_connect(proxy_host, proxy_port,
                                   target_host, target_port)
        print(f"  [✓] CONNECT 隧道建立成功")
        print(f"      通过 {proxy_host}:{proxy_port} → {target_host}:{target_port}")

        # 在隧道上建立 TLS 连接
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(tunnel_sock, server_hostname=target_host)
        print(f"  [✓] TLS 握手完成")
        print(f"      协议: {tls_sock.version()}")
        print(f"      密码套件: {tls_sock.cipher()[0]}")

        # 发送 HTTPS 请求
        request = (
            f'GET / HTTP/1.1\r\n'
            f'Host: {target_host}\r\n'
            f'Connection: close\r\n'
            f'\r\n'
        ).encode()
        tls_sock.sendall(request)

        # 接收响应
        response = b''
        while True:
            data = tls_sock.recv(4096)
            if not data:
                break
            response += data

        tls_sock.close()

        # 显示结果
        status = response.split(b'\r\n')[0].decode()
        print(f"  [✓] HTTPS 响应: {status}")
        print(f"      响应大小: {len(response)} bytes")
        print()
        print("  关键点:")
        print("    - 代理只能看到 CONNECT example.com:443")
        print("    - TLS 数据对代理完全不透明")
        print("    - 这就是 HTTPS 代理的工作原理")

    except ConnectionRefusedError:
        print(f"  [!] 无法连接代理 {proxy_host}:{proxy_port}")
        print(f"      请先启动: python3 http_proxy.py")
    except Exception as e:
        print(f"  [!] 错误: {e}")


def test_tcp_tunnel():
    """测试通过 HTTP CONNECT 建立任意 TCP 隧道"""
    print()
    print("[测试 2] 任意 TCP 协议通过 HTTP 隧道")
    print("  场景: TCP Echo 通过 HTTP CONNECT 隧道")
    print()

    proxy_host = '127.0.0.1'
    proxy_port = 8080

    # 启动一个简单的 echo 服务器
    echo_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    echo_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo_server.bind(('127.0.0.1', 9876))
    echo_server.listen(1)

    def echo_handler():
        conn, _ = echo_server.accept()
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b'ECHO: ' + data)
        conn.close()
        echo_server.close()

    thread = threading.Thread(target=echo_handler, daemon=True)
    thread.start()
    time.sleep(0.2)

    try:
        # 通过 HTTP CONNECT 隧道连接 echo 服务
        tunnel = http_connect(proxy_host, proxy_port, '127.0.0.1', 9876)
        print(f"  [✓] 隧道建立: proxy → 127.0.0.1:9876")

        # 通过隧道发送数据
        messages = [b'Hello', b'World', b'Via HTTP Tunnel']
        for msg in messages:
            tunnel.sendall(msg)
            response = tunnel.recv(1024)
            expected = b'ECHO: ' + msg
            status = '✓' if response == expected else '✗'
            print(f"  [{status}] 发送: {msg.decode()} → 收到: {response.decode()}")

        tunnel.close()
        print()
        print("  关键点:")
        print("    - 任意 TCP 协议都可以通过 HTTP CONNECT 隧道传输")
        print("    - SSH, SMTP, 自定义协议都可以穿透 HTTP 代理")

    except ConnectionRefusedError:
        print(f"  [!] 无法连接代理")
    except Exception as e:
        print(f"  [!] 错误: {e}")


def demo_tunnel_detection():
    """演示隧道检测和防御"""
    print()
    print("[补充] HTTP 隧道检测与防御")
    print("=" * 50)
    print()
    print("企业防火墙检测 HTTP 隧道的方法:")
    print()
    print("  1. 端口限制:")
    print("     - 只允许 CONNECT 到 443 (HTTPS)")
    print("     - 阻止 CONNECT 到非标准端口")
    print()
    print("  2. 流量分析:")
    print("     - CONNECT 后的流量应该是 TLS ClientHello")
    print("     - 如果不是 TLS → 可能是隧道滥用")
    print()
    print("  3. 连接时长:")
    print("     - 长期保持的 CONNECT 连接可能是 SSH 隧道")
    print()
    print("  4. 流量模式:")
    print("     - 正常 HTTPS: 短突发 + 长间隔")
    print("     - SSH 隧道: 持续小包 (心跳)")
    print()
    print("绕过检测的技术:")
    print("  - 伪装为合法 TLS 流量 (域前置)")
    print("  - WebSocket 隧道 (看起来像正常 Web 应用)")
    print("  - HTTP/2 复用 (与正常流量混合)")


def main():
    print("=" * 60)
    print("HTTP 隧道客户端测试")
    print("=" * 60)
    print()

    test_https_via_connect()
    test_tcp_tunnel()
    demo_tunnel_detection()

    print()
    print("=" * 60)
    print("总结:")
    print("  HTTP CONNECT 是最广泛使用的隧道机制")
    print("  它是 HTTPS 代理的核心，也是穿越防火墙的关键技术")
    print("  理解 CONNECT 有助于理解企业网络架构和安全策略")
    print("=" * 60)


if __name__ == '__main__':
    main()
