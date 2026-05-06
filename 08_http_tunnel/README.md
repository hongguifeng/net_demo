# 第八章：HTTP 隧道与 CONNECT

## 原理

HTTP 隧道利用 HTTP 协议来传输非 HTTP 的任意 TCP 流量，常用于穿越只允许 HTTP 的防火墙。

### HTTP CONNECT 方法

```
Client                    HTTP Proxy                     Target Server
  │                          │                               │
  │── CONNECT host:443 ────→│                               │
  │   HTTP/1.1              │── TCP Connect ──────────────→│
  │                          │                               │
  │←── HTTP/1.1 200 ────────│←──────────────────────────────│
  │    Connection Established│                               │
  │                          │                               │
  │←═══════ TLS / 任意协议数据 直接透传 ══════════════════→│
  │                          │                               │
```

### HTTP CONNECT vs SOCKS5

| 特性 | HTTP CONNECT | SOCKS5 |
|------|-------------|--------|
| 协议 | HTTP | 二进制 |
| 支持 | 仅 TCP | TCP + UDP |
| 穿墙 | 更容易 (看起来像 HTTP) | 可能被阻断 |
| 认证 | HTTP Basic/Bearer | 用户名密码 |
| 使用场景 | HTTPS 代理 | 通用代理 |

### HTTP 隧道的高级用法

1. **WebSocket 隧道**: 利用 WebSocket 的全双工特性传输任意数据
2. **HTTP/2 隧道**: 多路复用，单连接承载多个流
3. **伪装**: 将隧道流量伪装为正常 HTTP 请求

### 安全考虑

```
正常 HTTPS:
  Client → [HTTP CONNECT] → Proxy → [TLS] → Server
  代理只能看到目标地址，看不到 TLS 内的数据

隧道滥用风险:
  - 恶意软件通过 CONNECT 建立 C2 通道
  - 数据泄露 (通过代理外传数据)
  - 防御: 限制 CONNECT 端口、检测异常连接模式
```

## 示例代码

| 文件 | 说明 |
|------|------|
| `http_proxy.py` | HTTP CONNECT 代理服务器 |
| `http_tunnel_client.py` | 通过 HTTP 隧道建立连接 |
| `websocket_tunnel.py` | WebSocket 隧道实现 |

## 运行

```bash
# 终端1: 启动 HTTP 代理
python3 http_proxy.py

# 终端2: 通过隧道连接
python3 http_tunnel_client.py

# 测试:
# curl -x http://127.0.0.1:8080 https://example.com
# curl -p -x http://127.0.0.1:8080 http://example.com
```
