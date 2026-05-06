#!/usr/bin/env python3
"""
SOCKS5 代理服务器完整实现

原理：
  SOCKS5 代理服务器接收客户端的连接请求，代替客户端连接目标服务器，
  然后在两者之间双向转发数据。

  协议实现步骤：
  1. 接受客户端连接
  2. 协商认证方法
  3. (可选) 执行认证
  4. 处理连接请求 (解析目标地址)
  5. 连接目标服务器
  6. 双向转发数据

  支持特性：
  - CONNECT 命令 (TCP 代理)
  - IPv4 / 域名 / IPv6 地址类型
  - 无认证 / 用户名密码认证
  - 并发连接 (多线程)

运行方式：
  python3 socks5_server.py [端口]
  python3 socks5_server.py 1080

验证方法：
  # 使用 curl 通过代理访问
  curl --socks5 127.0.0.1:1080 http://httpbin.org/ip
  curl --socks5-hostname 127.0.0.1:1080 http://example.com

  # 使用 Python 通过代理访问
  python3 socks5_client.py
"""

import socket
import struct
import threading
import select
import sys
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('socks5')

# SOCKS5 常量
SOCKS_VERSION = 5

# 认证方法
AUTH_NONE = 0x00
AUTH_USERNAME_PASSWORD = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# 命令
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# 地址类型
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# 回复状态
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ADDR_NOT_SUPPORTED = 0x08

# 配置
USERS = {
    'admin': 'password123',  # 仅演示用，生产环境应使用安全的认证
}
REQUIRE_AUTH = False  # 设为 True 启用用户名密码认证


class SOCKS5Connection:
    """处理单个 SOCKS5 连接"""

    def __init__(self, client_sock: socket.socket, client_addr: tuple):
        self.client = client_sock
        self.client_addr = client_addr
        self.remote = None

    def handle(self):
        """处理 SOCKS5 连接的完整生命周期"""
        try:
            # 步骤 1: 认证协商
            if not self.negotiate_auth():
                return

            # 步骤 2: 处理连接请求
            if not self.handle_request():
                return

            # 步骤 3: 双向数据转发
            self.relay_data()

        except Exception as e:
            logger.error(f"[{self.client_addr}] 错误: {e}")
        finally:
            self.client.close()
            if self.remote:
                self.remote.close()

    def negotiate_auth(self) -> bool:
        """
        协商认证方法

        客户端发送:
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+

        服务端回复:
        +----+--------+
        |VER | METHOD |
        +----+--------+
        """
        # 读取版本和方法数量
        header = self.client.recv(2)
        if len(header) < 2:
            return False

        version, nmethods = struct.unpack('!BB', header)
        if version != SOCKS_VERSION:
            logger.warning(f"[{self.client_addr}] 不支持的版本: {version}")
            return False

        # 读取支持的认证方法列表
        methods = self.client.recv(nmethods)
        method_list = list(methods)

        logger.debug(f"[{self.client_addr}] 客户端支持的认证方法: {method_list}")

        if REQUIRE_AUTH:
            if AUTH_USERNAME_PASSWORD in method_list:
                # 选择用户名密码认证
                self.client.send(struct.pack('!BB', SOCKS_VERSION,
                                             AUTH_USERNAME_PASSWORD))
                return self.authenticate_password()
            else:
                self.client.send(struct.pack('!BB', SOCKS_VERSION,
                                             AUTH_NO_ACCEPTABLE))
                return False
        else:
            # 无需认证
            self.client.send(struct.pack('!BB', SOCKS_VERSION, AUTH_NONE))
            return True

    def authenticate_password(self) -> bool:
        """
        用户名密码认证 (RFC 1929)

        请求:
        +----+------+----------+------+----------+
        |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        +----+------+----------+------+----------+

        响应:
        +----+--------+
        |VER | STATUS |
        +----+--------+
        STATUS: 0x00=成功
        """
        # 读取认证版本
        ver = self.client.recv(1)
        if ver != b'\x01':
            return False

        # 读取用户名
        ulen = self.client.recv(1)[0]
        username = self.client.recv(ulen).decode('utf-8')

        # 读取密码
        plen = self.client.recv(1)[0]
        password = self.client.recv(plen).decode('utf-8')

        # 验证 (安全注意：实际应用中应使用 bcrypt 等安全比较)
        if username in USERS and USERS[username] == password:
            self.client.send(b'\x01\x00')  # 成功
            logger.info(f"[{self.client_addr}] 认证成功: {username}")
            return True
        else:
            self.client.send(b'\x01\x01')  # 失败
            logger.warning(f"[{self.client_addr}] 认证失败: {username}")
            return False

    def handle_request(self) -> bool:
        """
        处理连接请求

        请求:
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        """
        # 读取请求头
        header = self.client.recv(4)
        if len(header) < 4:
            return False

        version, cmd, _, atyp = struct.unpack('!BBBB', header)

        if version != SOCKS_VERSION:
            return False

        # 解析目标地址
        dst_addr = self.parse_address(atyp)
        if dst_addr is None:
            self.send_reply(REP_ADDR_NOT_SUPPORTED)
            return False

        # 读取目标端口
        port_data = self.client.recv(2)
        dst_port = struct.unpack('!H', port_data)[0]

        logger.info(f"[{self.client_addr}] {self.cmd_name(cmd)} → "
                    f"{dst_addr}:{dst_port}")

        # 处理命令
        if cmd == CMD_CONNECT:
            return self.do_connect(dst_addr, dst_port)
        elif cmd == CMD_BIND:
            self.send_reply(REP_CMD_NOT_SUPPORTED)
            return False
        elif cmd == CMD_UDP_ASSOCIATE:
            self.send_reply(REP_CMD_NOT_SUPPORTED)
            return False
        else:
            self.send_reply(REP_CMD_NOT_SUPPORTED)
            return False

    def parse_address(self, atyp: int) -> str:
        """解析不同类型的目标地址"""
        if atyp == ATYP_IPV4:
            # 4 字节 IPv4 地址
            raw = self.client.recv(4)
            return socket.inet_ntoa(raw)

        elif atyp == ATYP_DOMAIN:
            # 域名: 1 字节长度 + 域名
            domain_len = self.client.recv(1)[0]
            domain = self.client.recv(domain_len).decode('utf-8')
            return domain

        elif atyp == ATYP_IPV6:
            # 16 字节 IPv6 地址
            raw = self.client.recv(16)
            return socket.inet_ntop(socket.AF_INET6, raw)

        return None

    def do_connect(self, dst_addr: str, dst_port: int) -> bool:
        """执行 CONNECT 命令：连接到目标服务器"""
        try:
            # 创建到目标的连接
            self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.remote.settimeout(10)
            self.remote.connect((dst_addr, dst_port))
            self.remote.settimeout(None)

            # 获取本地绑定地址
            bind_addr, bind_port = self.remote.getsockname()

            # 发送成功响应
            self.send_reply(REP_SUCCESS, bind_addr, bind_port)

            logger.info(f"[{self.client_addr}] 连接成功 → {dst_addr}:{dst_port}")
            return True

        except socket.timeout:
            self.send_reply(REP_TTL_EXPIRED)
            logger.warning(f"[{self.client_addr}] 连接超时: {dst_addr}:{dst_port}")
        except ConnectionRefusedError:
            self.send_reply(REP_CONNECTION_REFUSED)
            logger.warning(f"[{self.client_addr}] 连接被拒绝: {dst_addr}:{dst_port}")
        except OSError as e:
            if 'Network is unreachable' in str(e):
                self.send_reply(REP_NETWORK_UNREACHABLE)
            else:
                self.send_reply(REP_HOST_UNREACHABLE)
            logger.warning(f"[{self.client_addr}] 连接失败: {e}")

        return False

    def send_reply(self, rep: int, bind_addr: str = '0.0.0.0',
                   bind_port: int = 0):
        """
        发送连接响应

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        """
        reply = struct.pack('!BBBB', SOCKS_VERSION, rep, 0x00, ATYP_IPV4)
        reply += socket.inet_aton(bind_addr)
        reply += struct.pack('!H', bind_port)
        self.client.send(reply)

    def relay_data(self):
        """
        双向数据转发

        使用 select() 同时监控两个方向的数据流：
        - client → remote
        - remote → client

        当任一方关闭连接时，停止转发。
        """
        sockets = [self.client, self.remote]
        total_bytes = 0

        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 60)

            if exceptional:
                break

            if not readable:
                # 超时
                break

            for sock in readable:
                if sock is self.client:
                    data = self.client.recv(4096)
                    if not data:
                        return
                    self.remote.sendall(data)
                    total_bytes += len(data)
                elif sock is self.remote:
                    data = self.remote.recv(4096)
                    if not data:
                        return
                    self.client.sendall(data)
                    total_bytes += len(data)

        logger.debug(f"[{self.client_addr}] 转发结束，共 {total_bytes} bytes")

    @staticmethod
    def cmd_name(cmd: int) -> str:
        names = {CMD_CONNECT: 'CONNECT', CMD_BIND: 'BIND',
                 CMD_UDP_ASSOCIATE: 'UDP'}
        return names.get(cmd, f'Unknown({cmd})')


class SOCKS5Server:
    """SOCKS5 代理服务器"""

    def __init__(self, host: str = '127.0.0.1', port: int = 1080):
        self.host = host
        self.port = port
        self.server_sock = None

    def start(self):
        """启动服务器"""
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(128)

        logger.info(f"SOCKS5 代理服务器启动: {self.host}:{self.port}")
        logger.info(f"认证: {'用户名密码' if REQUIRE_AUTH else '无需认证'}")
        logger.info(f"测试: curl --socks5 {self.host}:{self.port} http://example.com")
        logger.info(f"按 Ctrl+C 停止")
        print()

        try:
            while True:
                client_sock, client_addr = self.server_sock.accept()
                logger.info(f"新连接: {client_addr}")

                # 每个连接一个线程
                conn = SOCKS5Connection(client_sock, client_addr)
                thread = threading.Thread(target=conn.handle, daemon=True)
                thread.start()

        except KeyboardInterrupt:
            logger.info("服务器停止")
        finally:
            self.server_sock.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080

    print("=" * 60)
    print("SOCKS5 代理服务器")
    print("=" * 60)
    print()

    server = SOCKS5Server('127.0.0.1', port)
    server.start()


if __name__ == '__main__':
    main()
