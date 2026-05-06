# 第二章：IP 数据包构造与路由

## 原理

### IPv4 头部格式

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 关键概念

1. **IP 分片 (Fragmentation)**
   - 当数据包超过链路 MTU 时，路由器会将其分片
   - 分片通过 Identification + Fragment Offset 重组
   - DF (Don't Fragment) 标志位禁止分片

2. **TTL (Time To Live)**
   - 每经过一个路由器 TTL 减 1
   - TTL=0 时包被丢弃，发送 ICMP Time Exceeded
   - traceroute 就是利用逐步增加 TTL 来发现路径

3. **IP 路由**
   - 最长前缀匹配 (Longest Prefix Match)
   - 路由表结构：目的网段 + 下一跳 + 接口

4. **校验和计算**
   - 仅覆盖 IP 头部
   - 16 位反码求和

## 示例代码

| 文件 | 说明 |
|------|------|
| `ip_packet.py` | 手动构造 IP 数据包 |
| `traceroute.py` | 实现简易 traceroute |
| `fragment.py` | IP 分片与重组演示 |

## 运行

```bash
sudo python3 ip_packet.py
sudo python3 traceroute.py 8.8.8.8
sudo python3 fragment.py
```
