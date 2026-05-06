#!/usr/bin/env python3
"""
HTTP CONNECT 代理服务器

原理：
  HTTP 代理服务器支持两种模式：
  1. 普通代理 (GET/POST): 代理转发 HTTP 请求
  2. CONNECT 隧道: 建立 TCP 隧道，透传任意数据

  CONNECT 流程：
  1. 客户端发送: CONNECT target:port HTTP/1.1
  2. 代理连接到 target:port
  3. 代理返回: HTTP/1.1 200 Connection Established
  4. 之后所有数据在 client ↔ target 之间透传

  这就是 HTTPS 代理的工作方式：
  - 代理不能解密 TLS 数据（除非 MITM）
  - 代理只知道目标地址和端口

运行方式：
  python3 http_proxy.py [端口]

验证方法：
  # HTTPS (CONNECT 隧道)
  curl -x http://127.0.0.1:8080 https://example.com

  # HTTP (普通代理)
  curl -x http://127.0.0.1:8080 http://example.com

  # 也可以设置环境变量
  export http_proxy=http://127.0.0.1:8080
  export https_proxy=http://127.0.0.1:8080
  curl https://example.com
"""

import socket
import select
import threading
import sys
import logging
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('http-proxy')


class HTTPProxyHandler:
    """处理单个 HTTP 代理连接"""

    def __init__(self, client_sock: socket.socket, client_addr: tuple):
        self.client = client_sock
        self.client_addr = client_addr

    def handle(self):
        """处理代理请求"""
        try:
            # 读取请求行
            request_line = self._read_line()
            if not request_line:
                return

            logger.info(f"[{self.client_addr[0]}:{self.client_addr[1]}] "
                        f"{request_line.strip()}")

            # 解析请求方法
            parts = request_line.split()
            if len(parts) < 3:
                self._send_error(400, "Bad Request")
                return

            method = parts[0].upper()

            if method == 'CONNECT':
                # CONNECT 隧道模式
                self._handle_connect(parts[1])
            else:
                # 普通 HTTP 代理
                self._handle_http(method, parts[1], parts[2])

        except Exception as e:
            logger.error(f"[{self.client_addr}] 错误: {e}")
        finally:
            self.client.close()

    def _handle_connect(self, target: str):
        """
        处理 CONNECT 请求 (建立隧道)

        流程：
        1. 解析目标 host:port
        2. 读取并丢弃剩余请求头
        3. 连接目标服务器
        4. 返回 200 Connection Established
        5. 双向透传数据
        """
        # 解析目标地址
        host, port = self._parse_target(target)
        if not host:
            self._send_error(400, "Bad Request")
            return

        # 读取剩余的请求头 (直到空行)
        while True:
            line = self._read_line()
            if not line or line.strip() == '':
                break

        # 连接目标服务器
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((host, port))
            remote.settimeout(None)
        except Exception as e:
            self._send_error(502, f"Bad Gateway: {e}")
            return

        # 发送成功响应
        response = b'HTTP/1.1 200 Connection Established\r\n'
        response += b'Proxy-Agent: Python-HTTP-Proxy\r\n'
        response += b'\r\n'
        self.client.sendall(response)

        logger.info(f"  CONNECT 隧道建立: {host}:{port}")

        # 双向透传
        self._relay(remote)
        remote.close()

    def _handle_http(self, method: str, url: str, version: str):
        """
        处理普通 HTTP 代理请求

        流程：
        1. 解析完整 URL 获取目标 host:port
        2. 读取所有请求头
        3. 连接目标服务器
        4. 转发请求 (去掉完整 URL，改为相对路径)
        5. 转发响应
        """
        # 解析 URL: http://host:port/path
        match = re.match(r'http://([^/:]+)(?::(\d+))?(/.*)$', url)
        if not match:
            self._send_error(400, "Invalid URL")
            return

        host = match.group(1)
        port = int(match.group(2)) if match.group(2) else 80
        path = match.group(3)

        # 读取请求头
        headers = []
        content_length = 0
        while True:
            line = self._read_line()
            if not line or line.strip() == '':
                break
            headers.append(line)
            if line.lower().startswith('content-length:'):
                content_length = int(line.split(':')[1].strip())

        # 连接目标
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((host, port))
            remote.settimeout(None)
        except Exception as e:
            self._send_error(502, f"Bad Gateway: {e}")
            return

        # 转发请求 (改为相对路径)
        request = f'{method} {path} {version}\r\n'.encode()
        for header in headers:
            # 跳过 Proxy-* 头
            if not header.lower().startswith('proxy-'):
                request += header.encode() + b'\r\n'
        request += b'\r\n'

        # 如果有请求体
        if content_length > 0:
            body = self.client.recv(content_length)
            request += body

        remote.sendall(request)

        # 转发响应
        while True:
            data = remote.recv(4096)
            if not data:
                break
            self.client.sendall(data)

        remote.close()
        logger.info(f"  HTTP 代理完成: {method} {host}:{port}{path}")

    def _relay(self, remote: socket.socket):
        """双向数据透传"""
        sockets = [self.client, remote]
        while True:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
            except (ValueError, OSError):
                break

            if exceptional:
                break
            if not readable:
                break  # 超时

            for sock in readable:
                try:
                    data = sock.recv(8192)
                    if not data:
                        return
                    if sock is self.client:
                        remote.sendall(data)
                    else:
                        self.client.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

    def _parse_target(self, target: str) -> tuple:
        """解析 host:port"""
        if ':' in target:
            parts = target.rsplit(':', 1)
            return parts[0], int(parts[1])
        return target, 443  # CONNECT 默认 443

    def _read_line(self) -> str:
        """读取一行 (直到 \\r\\n)"""
        data = b''
        while True:
            byte = self.client.recv(1)
            if not byte:
                return ''
            data += byte
            if data.endswith(b'\r\n'):
                return data.decode('utf-8', errors='replace').rstrip('\r\n')
            if len(data) > 8192:  # 防止 header 过长
                return ''

    def _send_error(self, code: int, message: str):
        """发送 HTTP 错误响应"""
        body = f'<h1>{code} {message}</h1>'.encode()
        response = f'HTTP/1.1 {code} {message}\r\n'.encode()
        response += b'Content-Type: text/html\r\n'
        response += f'Content-Length: {len(body)}\r\n'.encode()
        response += b'Connection: close\r\n'
        response += b'\r\n'
        response += body
        self.client.sendall(response)


class HTTPProxyServer:
    """HTTP 代理服务器"""

    def __init__(self, host: str = '127.0.0.1', port: int = 8080):
        self.host = host
        self.port = port

    def start(self):
        """启动服务器"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(128)

        logger.info(f"HTTP 代理服务器启动: {self.host}:{self.port}")
        logger.info(f"支持: HTTP 代理 + CONNECT 隧道")
        logger.info(f"测试: curl -x http://{self.host}:{self.port} https://example.com")
        print()

        try:
            while True:
                client_sock, client_addr = server.accept()
                handler = HTTPProxyHandler(client_sock, client_addr)
                thread = threading.Thread(target=handler.handle, daemon=True)
                thread.start()
        except KeyboardInterrupt:
            logger.info("服务器停止")
        finally:
            server.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    print("=" * 60)
    print("HTTP CONNECT 代理服务器")
    print("=" * 60)
    print()

    server = HTTPProxyServer('127.0.0.1', port)
    server.start()


if __name__ == '__main__':
    main()
