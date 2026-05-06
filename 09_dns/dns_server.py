#!/usr/bin/env python3
"""
简易 DNS 服务器

原理：
  DNS 服务器接收查询请求，根据本地记录或转发到上游服务器来响应。
  本实现支持：
  - 本地区域记录 (zone file)
  - 上游转发 (递归解析)
  - A, AAAA, CNAME, MX, TXT 记录

  这帮助理解 DNS 服务器的内部工作机制。

运行方式：
  python3 dns_server.py [端口]
  python3 dns_server.py 5353

验证方法：
  dig @127.0.0.1 -p 5353 test.local
  dig @127.0.0.1 -p 5353 example.com  (会转发到上游)
  nslookup test.local 127.0.0.1 -port=5353
"""

import socket
import struct
import sys
import threading
import time


# 本地 DNS 记录 (模拟 zone file)
LOCAL_RECORDS = {
    'test.local': {
        'A': ['192.168.1.100'],
        'AAAA': ['fd00::1'],
        'TXT': ['v=spf1 include:test.local ~all'],
    },
    'www.test.local': {
        'CNAME': ['test.local'],
    },
    'mail.test.local': {
        'A': ['192.168.1.200'],
        'MX': [(10, 'mail.test.local')],
    },
    'test.local.': {
        'NS': ['ns1.test.local'],
    },
    'ns1.test.local': {
        'A': ['127.0.0.1'],
    },
}

# 记录类型到数值的映射
TYPE_MAP = {'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28}
TYPE_MAP_REV = {v: k for k, v in TYPE_MAP.items()}


def encode_domain(domain: str) -> bytes:
    """编码域名"""
    encoded = b''
    for label in domain.rstrip('.').split('.'):
        encoded += struct.pack('B', len(label)) + label.encode('ascii')
    encoded += b'\x00'
    return encoded


def decode_domain(data: bytes, offset: int) -> tuple:
    """解码域名 (支持指针压缩)"""
    labels = []
    original_offset = offset
    jumped = False

    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode('ascii'))
            offset += length

    return '.'.join(labels), original_offset if jumped else offset


def build_response(query_data: bytes, answers: list) -> bytes:
    """
    构造 DNS 响应消息

    参数:
        query_data: 原始查询数据 (用于复制 Header 和 Question)
        answers: 回答记录列表 [(name, type, class, ttl, rdata_bytes), ...]
    """
    # 复制查询的 Header，修改标志位
    trans_id = struct.unpack('!H', query_data[:2])[0]

    # 设置响应标志: QR=1, AA=1, RD=1, RA=1
    flags = 0x8580  # QR=1, AA=1, RD=1, RA=1, RCODE=0

    # 解析问题数
    qdcount = struct.unpack('!H', query_data[4:6])[0]
    ancount = len(answers)

    # 构造头部
    header = struct.pack('!HHHHHH',
                         trans_id, flags, qdcount, ancount, 0, 0)

    # 复制问题部分
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_domain(query_data, offset)
        offset += 4  # QTYPE + QCLASS

    question = query_data[12:offset]

    # 构造回答部分
    answer_section = b''
    for name, rtype, rclass, ttl, rdata in answers:
        answer_section += encode_domain(name)
        answer_section += struct.pack('!HHIH', rtype, rclass, ttl, len(rdata))
        answer_section += rdata

    return header + question + answer_section


def build_nxdomain(query_data: bytes) -> bytes:
    """构造 NXDOMAIN 响应"""
    trans_id = struct.unpack('!H', query_data[:2])[0]
    flags = 0x8583  # QR=1, AA=1, RD=1, RA=1, RCODE=3(NXDOMAIN)
    qdcount = struct.unpack('!H', query_data[4:6])[0]

    header = struct.pack('!HHHHHH', trans_id, flags, qdcount, 0, 0, 0)

    # 复制问题部分
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_domain(query_data, offset)
        offset += 4
    question = query_data[12:offset]

    return header + question


def encode_rdata(rtype: str, value) -> bytes:
    """编码资源记录数据"""
    if rtype == 'A':
        return socket.inet_aton(value)
    elif rtype == 'AAAA':
        return socket.inet_pton(socket.AF_INET6, value)
    elif rtype == 'CNAME' or rtype == 'NS':
        return encode_domain(value)
    elif rtype == 'MX':
        priority, exchange = value
        return struct.pack('!H', priority) + encode_domain(exchange)
    elif rtype == 'TXT':
        txt_bytes = value.encode('utf-8')
        return struct.pack('B', len(txt_bytes)) + txt_bytes
    return b''


def lookup_local(qname: str, qtype_num: int) -> list:
    """
    在本地记录中查找

    返回: [(name, type_num, class, ttl, rdata_bytes), ...]
    """
    qtype = TYPE_MAP_REV.get(qtype_num, '')
    answers = []

    # 查找记录
    records = LOCAL_RECORDS.get(qname, {})

    if qtype in records:
        for value in records[qtype]:
            rdata = encode_rdata(qtype, value)
            answers.append((qname, qtype_num, 1, 3600, rdata))

    elif 'CNAME' in records and qtype != 'CNAME':
        # CNAME 重定向
        for cname in records['CNAME']:
            rdata = encode_rdata('CNAME', cname)
            answers.append((qname, TYPE_MAP['CNAME'], 1, 3600, rdata))
            # 继续解析 CNAME 目标
            cname_answers = lookup_local(cname, qtype_num)
            answers.extend(cname_answers)

    return answers


def forward_query(query_data: bytes, upstream: str = '8.8.8.8') -> bytes:
    """转发查询到上游 DNS 服务器"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(query_data, (upstream, 53))
        response, _ = sock.recvfrom(4096)
        return response
    except socket.timeout:
        return build_nxdomain(query_data)
    finally:
        sock.close()


class DNSServer:
    """简易 DNS 服务器"""

    def __init__(self, host: str = '127.0.0.1', port: int = 5353,
                 upstream: str = '8.8.8.8'):
        self.host = host
        self.port = port
        self.upstream = upstream
        self.stats = {'queries': 0, 'local_hits': 0, 'forwards': 0}

    def start(self):
        """启动 DNS 服务器"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))

        print(f"DNS 服务器启动: {self.host}:{self.port}")
        print(f"上游 DNS: {self.upstream}")
        print(f"本地记录: {len(LOCAL_RECORDS)} 条")
        print(f"测试: dig @{self.host} -p {self.port} test.local")
        print()

        try:
            while True:
                data, addr = sock.recvfrom(4096)
                self.stats['queries'] += 1

                # 在线程中处理查询
                thread = threading.Thread(
                    target=self.handle_query,
                    args=(sock, data, addr),
                    daemon=True
                )
                thread.start()

        except KeyboardInterrupt:
            print(f"\n服务器停止. 统计:")
            print(f"  总查询: {self.stats['queries']}")
            print(f"  本地命中: {self.stats['local_hits']}")
            print(f"  转发: {self.stats['forwards']}")
        finally:
            sock.close()

    def handle_query(self, sock: socket.socket, data: bytes, addr: tuple):
        """处理单个 DNS 查询"""
        try:
            # 解析查询
            if len(data) < 12:
                return

            offset = 12
            qname, offset = decode_domain(data, offset)
            qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])

            qtype_name = TYPE_MAP_REV.get(qtype, str(qtype))
            print(f"  [{addr[0]}:{addr[1]}] 查询: {qname} {qtype_name}")

            # 先查本地记录
            answers = lookup_local(qname, qtype)

            if answers:
                # 本地命中
                response = build_response(data, answers)
                self.stats['local_hits'] += 1
                print(f"    → 本地回答: {len(answers)} 条记录")
            else:
                # 转发到上游
                response = forward_query(data, self.upstream)
                self.stats['forwards'] += 1
                print(f"    → 转发到 {self.upstream}")

            sock.sendto(response, addr)

        except Exception as e:
            print(f"  [错误] {e}")
            # 返回 SERVFAIL
            if len(data) >= 12:
                error_resp = build_nxdomain(data)
                sock.sendto(error_resp, addr)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5353

    print("=" * 60)
    print("简易 DNS 服务器")
    print("=" * 60)
    print()
    print("本地记录:")
    for domain, records in LOCAL_RECORDS.items():
        for rtype, values in records.items():
            for val in values:
                print(f"  {domain}\tIN\t{rtype}\t{val}")
    print()

    server = DNSServer('127.0.0.1', port)
    server.start()


if __name__ == '__main__':
    main()
