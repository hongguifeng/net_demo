#!/usr/bin/env python3
"""
DNS 解析器 - 从零实现 DNS 协议查询

原理：
  DNS 使用 UDP 端口 53 通信（也支持 TCP 用于大响应）。
  本实现手动构造 DNS 查询包，解析响应包，不使用任何 DNS 库。

  DNS 查询过程：
  1. 构造 DNS 查询消息 (Header + Question)
  2. 通过 UDP 发送到 DNS 服务器
  3. 接收并解析响应消息

  域名编码 (如 www.example.com):
  ┌───┬─────────┬───┬─────────────┬───┬─────┬───┐
  │ 3 │ w w w   │ 7 │ e x a m p l e│ 3 │ com │ 0 │
  └───┴─────────┴───┴─────────────┴───┴─────┴───┘
  每段前面加一个长度字节，最后以 0 结束

运行方式：
  python3 dns_resolver.py [域名] [DNS服务器]
  python3 dns_resolver.py example.com 8.8.8.8

验证方法：
  dig example.com @8.8.8.8
  nslookup example.com 8.8.8.8
"""

import socket
import struct
import sys
import random
import time


# DNS 记录类型
RECORD_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    257: 'CAA',
}

# DNS 响应码
RCODES = {
    0: 'No Error',
    1: 'Format Error',
    2: 'Server Failure',
    3: 'Name Error (NXDOMAIN)',
    4: 'Not Implemented',
    5: 'Refused',
}


def encode_domain(domain: str) -> bytes:
    """
    编码域名为 DNS wire format

    www.example.com → \x03www\x07example\x03com\x00

    规则：
    - 每个标签前加一个长度字节
    - 以 \x00 (空标签) 结束
    - 单个标签最长 63 字节
    - 总长度最长 253 字节
    """
    encoded = b''
    for label in domain.rstrip('.').split('.'):
        if len(label) > 63:
            raise ValueError(f"DNS 标签过长: {label}")
        encoded += struct.pack('B', len(label)) + label.encode('ascii')
    encoded += b'\x00'
    return encoded


def decode_domain(data: bytes, offset: int) -> tuple:
    """
    解码 DNS wire format 的域名

    支持指针压缩 (pointer compression):
    - 如果长度字节的高两位为 11，表示这是一个指针
    - 指针的后 14 位是偏移量，指向消息中的另一个位置

    返回: (域名字符串, 新偏移量)
    """
    labels = []
    original_offset = offset
    jumped = False
    max_jumps = 10  # 防止循环指针

    jumps = 0
    while True:
        if offset >= len(data):
            break

        length = data[offset]

        if length == 0:
            # 域名结束
            offset += 1
            break

        elif (length & 0xC0) == 0xC0:
            # 指针压缩: 高两位为 11
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                raise ValueError("DNS 指针循环")

        else:
            # 正常标签
            offset += 1
            label = data[offset:offset + length].decode('ascii')
            labels.append(label)
            offset += length

    domain = '.'.join(labels)
    return domain, original_offset if jumped else offset


def build_query(domain: str, qtype: int = 1, qclass: int = 1) -> bytes:
    """
    构造 DNS 查询消息

    Header (12 bytes):
    - ID: 随机 16 位标识符 (匹配请求和响应)
    - Flags: RD=1 (请求递归解析)
    - QDCOUNT: 1 (一个问题)
    - ANCOUNT, NSCOUNT, ARCOUNT: 0

    Question:
    - QNAME: 编码的域名
    - QTYPE: 查询类型 (A=1, AAAA=28, MX=15...)
    - QCLASS: IN=1 (Internet)
    """
    # 生成随机事务 ID
    transaction_id = random.randint(0, 0xFFFF)

    # 构造头部
    flags = 0x0100  # QR=0(查询), RD=1(请求递归)
    header = struct.pack('!HHHHHH',
                         transaction_id,
                         flags,
                         1,    # QDCOUNT: 1 个问题
                         0,    # ANCOUNT
                         0,    # NSCOUNT
                         0)    # ARCOUNT

    # 构造问题部分
    question = encode_domain(domain)
    question += struct.pack('!HH', qtype, qclass)

    return header + question, transaction_id


def parse_response(data: bytes) -> dict:
    """
    解析 DNS 响应消息

    返回: {
        'id': 事务ID,
        'flags': 标志字段,
        'rcode': 响应码,
        'questions': [...],
        'answers': [...],
        'authorities': [...],
        'additionals': [...]
    }
    """
    if len(data) < 12:
        raise ValueError("响应数据太短")

    # 解析头部
    (trans_id, flags, qdcount, ancount,
     nscount, arcount) = struct.unpack('!HHHHHH', data[:12])

    result = {
        'id': trans_id,
        'flags': flags,
        'qr': (flags >> 15) & 1,
        'opcode': (flags >> 11) & 0xF,
        'aa': (flags >> 10) & 1,
        'tc': (flags >> 9) & 1,
        'rd': (flags >> 8) & 1,
        'ra': (flags >> 7) & 1,
        'rcode': flags & 0xF,
        'rcode_name': RCODES.get(flags & 0xF, 'Unknown'),
        'questions': [],
        'answers': [],
        'authorities': [],
        'additionals': [],
    }

    offset = 12

    # 解析问题部分
    for _ in range(qdcount):
        qname, offset = decode_domain(data, offset)
        qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
        offset += 4
        result['questions'].append({
            'name': qname,
            'type': RECORD_TYPES.get(qtype, str(qtype)),
            'class': qclass,
        })

    # 解析资源记录 (Answer, Authority, Additional)
    def parse_records(count):
        nonlocal offset
        records = []
        for _ in range(count):
            name, offset = decode_domain(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack(
                '!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            record = {
                'name': name,
                'type': RECORD_TYPES.get(rtype, str(rtype)),
                'type_num': rtype,
                'class': rclass,
                'ttl': ttl,
                'rdata_raw': rdata,
            }

            # 解析具体记录类型
            if rtype == 1:  # A
                record['rdata'] = socket.inet_ntoa(rdata)
            elif rtype == 28:  # AAAA
                record['rdata'] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == 5:  # CNAME
                cname, _ = decode_domain(data, offset - rdlength)
                record['rdata'] = cname
            elif rtype == 2:  # NS
                ns, _ = decode_domain(data, offset - rdlength)
                record['rdata'] = ns
            elif rtype == 15:  # MX
                priority = struct.unpack('!H', rdata[:2])[0]
                mx, _ = decode_domain(data, offset - rdlength + 2)
                record['rdata'] = f"{priority} {mx}"
            elif rtype == 16:  # TXT
                txt_len = rdata[0]
                record['rdata'] = rdata[1:1 + txt_len].decode('utf-8', errors='replace')
            else:
                record['rdata'] = rdata.hex()

            records.append(record)
        return records

    result['answers'] = parse_records(ancount)
    result['authorities'] = parse_records(nscount)
    result['additionals'] = parse_records(arcount)

    return result


def resolve(domain: str, dns_server: str = '8.8.8.8',
            qtype: int = 1, timeout: float = 5.0) -> dict:
    """
    执行 DNS 查询

    参数:
        domain: 要解析的域名
        dns_server: DNS 服务器地址
        qtype: 查询类型 (1=A, 28=AAAA, 15=MX, 16=TXT)
        timeout: 超时时间

    返回: 解析结果字典
    """
    query_data, trans_id = build_query(domain, qtype)

    # 通过 UDP 发送查询
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    start_time = time.time()
    sock.sendto(query_data, (dns_server, 53))

    try:
        response_data, _ = sock.recvfrom(4096)
        elapsed = (time.time() - start_time) * 1000  # ms
    except socket.timeout:
        sock.close()
        raise TimeoutError(f"DNS 查询超时 ({timeout}s)")
    finally:
        sock.close()

    # 解析响应
    result = parse_response(response_data)
    result['query_time_ms'] = elapsed
    result['server'] = dns_server

    # 验证事务 ID
    if result['id'] != trans_id:
        raise ValueError("事务 ID 不匹配！可能遭受 DNS 劫持")

    return result


def print_result(result: dict):
    """格式化输出 DNS 查询结果"""
    print(f"\n;; 响应码: {result['rcode_name']} (rcode={result['rcode']})")
    print(f";; 标志: QR={result['qr']} AA={result['aa']} "
          f"TC={result['tc']} RD={result['rd']} RA={result['ra']}")
    print(f";; 查询时间: {result['query_time_ms']:.1f} ms")
    print(f";; 服务器: {result['server']}#53")
    print()

    if result['questions']:
        print(";; QUESTION SECTION:")
        for q in result['questions']:
            print(f";  {q['name']}\t\t{q['type']}\tIN")
        print()

    if result['answers']:
        print(";; ANSWER SECTION:")
        for a in result['answers']:
            print(f"  {a['name']}\t{a['ttl']}\tIN\t{a['type']}\t{a['rdata']}")
        print()

    if result['authorities']:
        print(";; AUTHORITY SECTION:")
        for a in result['authorities']:
            print(f"  {a['name']}\t{a['ttl']}\tIN\t{a['type']}\t{a['rdata']}")
        print()

    if result['additionals']:
        print(";; ADDITIONAL SECTION:")
        for a in result['additionals']:
            print(f"  {a['name']}\t{a['ttl']}\tIN\t{a['type']}\t{a['rdata']}")
        print()


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else 'example.com'
    dns_server = sys.argv[2] if len(sys.argv) > 2 else '8.8.8.8'

    print("=" * 60)
    print("DNS 解析器 (从零实现)")
    print("=" * 60)

    # 查询 A 记录
    print(f"\n[查询 1] A 记录: {domain}")
    try:
        result = resolve(domain, dns_server, qtype=1)
        print_result(result)
    except Exception as e:
        print(f"  错误: {e}")

    # 查询 AAAA 记录
    print(f"[查询 2] AAAA 记录: {domain}")
    try:
        result = resolve(domain, dns_server, qtype=28)
        print_result(result)
    except Exception as e:
        print(f"  错误: {e}")

    # 查询 MX 记录
    print(f"[查询 3] MX 记录: {domain}")
    try:
        result = resolve(domain, dns_server, qtype=15)
        print_result(result)
    except Exception as e:
        print(f"  错误: {e}")

    # 查询 NS 记录
    print(f"[查询 4] NS 记录: {domain}")
    try:
        result = resolve(domain, dns_server, qtype=2)
        print_result(result)
    except Exception as e:
        print(f"  错误: {e}")

    print("=" * 60)
    print("验证: dig {0} @{1}".format(domain, dns_server))
    print("=" * 60)


if __name__ == '__main__':
    main()
