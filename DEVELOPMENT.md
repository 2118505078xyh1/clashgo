# 开发文档（架构 · 内核原理 · 协议 · 验证）

---

## 架构与目录说明

## 架构

ClashGo 是单二进制桌面客户端，所有组件都用 Go 编写并编译进同一个可执行文件：

```
main.go                 窗口、托盘、系统事件
ui/                     MyGo 原生 UI（5 个主导航 + 工具页）
internal/minikernel/    自研代理内核（数据面 + 控制面 + REST/WS）
internal/kernel/        内核生命周期封装（启动/重载/暂停/停止）
internal/controller/    UI → 内核的 REST/WebSocket 客户端
internal/runtime/       配置增强调度
internal/enhance/       纯数据增强（merge / seq / overlay / include / builtin）
internal/config/        设置与配置数据模型
internal/profile/       订阅/profile 管理
internal/sysproxy/      系统代理、PAC、守卫
internal/installer/     安装器（覆盖安装/卸载/快捷方式）

协议/底层库（全部纯标准库自研，零外部依赖）：
internal/yaml/          自研 YAML（tag/锚点/块标量）
internal/dnsproto/      DNS 线格式（A/AAAA/CNAME...）
internal/ssproto/       Shadowsocks 加密与协议
internal/ssrproto/      ShadowsocksR（CFB + auth_sha1_v4 + tls 混淆）
internal/vproto/        VMess（legacy/CFB/ChaCha20 + UDP）
internal/wgproto/       WireGuard（Noise_IKpsk2）
internal/ruleindex/     DomainTrie / IPTree / GeoIP / GeoSite
internal/quicproto/     真 QUIC v1（密钥/头保护/帧/ACK/握手/DATAGRAM/ChaCha20/拥塞控制/密钥更新/Retry）+ DoQ
internal/http3proto/    HTTP/3 帧 + QPACK（RFC 9204/7541）
internal/grpcproto/     gRPC 帧 + h2c + HPACK + 流控 + trailers
internal/ipstack/       用户态 IPv4/TCP/UDP/ICMP（TUN，46 测试 / 99.7% 覆盖）
internal/ws/            WebSocket
internal/webdavclient/  WebDAV（备份）
internal/winreg/        Windows 注册表（自启等）
```

内核与 UI 通过进程内的 HTTP + WebSocket 通信，接口兼容 Clash 控制协议：UI 不直接依赖内核的内部类型，只调用 `/version`、`/proxies`、`/connections`、`/traffic`、`/logs` 等端点。

## 自研内核设计

设计依据见 `KERNEL_PRINCIPLES.md`。核心思想：

1. **Metadata 是唯一枢纽**：入站产生它、规则读取它、出站消费它
2. **出站接口极薄**：只有 `DialContext(ctx, *Metadata)`，UDP 能力用可选接口
3. **规则保留配置顺序语义**：first-match-wins，数据结构只作为加速手段
4. **统计用装饰器包装连接**：显式注入，不用全局单例

内核分层：

```
入站(mixed: SOCKS5/HTTP/UDP/TUN) → Metadata → 规则匹配 → 出站(DIRECT/REJECT/SS/SSR/VMess/VLESS/Trojan/WG/Hysteria2/TUIC)
                                      │                         │
                                 preHandle(fake-ip反查)      transport(TCP/TLS/WS/gRPC h2c/QUIC+HTTP3)
                                                                  │
                                                             流量统计 + 连接追踪
```

阶段路线见 `KERNEL_PLAN.md`。

## UI 信息架构（对齐 Clash Verge Rev）

前端按 Clash Verge Rev（源码在 `D:/code/clash/clash-verge-rev`）的信息架构设计，
详细页面结构见 `UI_REFERENCE.md`。要点：

- 侧边栏为 8 项标准导航：首页 / 代理 / 订阅 / 连接 / 规则 / 日志 / 测试 / 设置，底部实时流量图
- 首页为卡片式：订阅、当前节点、网络设置（系统代理/TUN）、代理模式（规则/全局/直连）、
  流量统计、网站测试、IP 信息、Clash 信息、系统信息
- 默认启动页为首页（Verge 风格），保留用户 `start-page` 显式选择
- 后端通过进程内 REST/WebSocket 控制接口驱动内核，等价于 Verge 的
  `tauri-plugin-mihomo-api`（见 `PROTOCOLS.md`）

## 构建与验证

```bash
go build -o clashgo.exe .     # 编译
go test ./...                  # 测试
go vet ./...                   # 静态检查
bash verify.sh                 # 快速验证
bash build-setup.sh            # 生成安装包
```

截图渲染（headless）：

```bash
go run ./cmd/shot && mv -f shot-*.png screenshots/
```

## 约定

- 界面默认中文，不提供其它语言选项
- 版本号统一为 `0.1.0`（软件即内核）
- 项目内不出现竞品名称、密钥或本机路径
- 文档保持 README.md / DEVELOPMENT.md / TODO.md 三份，与实际状态一致

---

## 自研内核规划与进度

## 目标

全部使用自研的纯 Go 代理内核，不依赖任何第三方内核。已达成：

- **内核版本 = 软件版本**（统一 `0.1.0`）
- 不再显示"软件版本 / 内核版本"两套版本号
- 内核能力按需实现，不依赖外部项目的发布节奏
- 第三方内核代码与依赖已从项目中彻底移除

## 进度

### 阶段 0：数据契约 ✅
- Metadata（连接身份对象）
- ProxyAdapter / Rule / ProxyGroup 极薄接口
- 单元测试

### 阶段 1：流量转发 ✅
- SOCKS5 入站（CONNECT + UDP ASSOCIATE）
- HTTP 入站（CONNECT 隧道 + 普通代理）
- Mixed 端口 Peek 分流
- DIRECT / REJECT 出站
- 流量统计装饰器 + 连接追踪

### 阶段 2：规则分流 ✅
- DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / MATCH
- 配置顺序优先（first-match-wins）
- YAML 配置解析（兼容 Clash 格式）

### 阶段 3：远端代理 ✅
- Shadowsocks 出站（AEAD）
- VMess 出站（TCP/TLS/WS）
- VLESS 出站（含 xtls-rprx-vision）
- Trojan 出站（TLS）
- Selector / URLTest 代理组 + 并发延迟测试

### 阶段 4：DNS 与 TUN ✅
- 内置 DNS 服务（UDP + TCP）
- hosts / fake-ip 池 / 反查（fake-ip → 域名）
- TUN 虚拟网卡（sing-tun + gvisor/mipstack 用户态协议栈）
- fake-ip 与 TUN 联动（预处理器反查域名供规则匹配）

### 阶段 5：控制面 ✅
- Clash 兼容 REST API（proxies / rules / connections / configs / dns-query 等）
- WebSocket 流（traffic / logs / connections）
- Bearer 鉴权
- UI 通过 controller 包调用，不直接依赖内核内部类型

## 已知限制

- 规则类型暂不支持 GEOIP / GEOSITE / RULE-SET（依赖外部地理数据文件）
- 出站协议暂不支持 Hysteria / TUIC / WireGuard / SSR
- sniffer（TLS SNI / HTTP Host 嗅探）未实现；当前依赖客户端提供域名或 fake-ip 反查
- TUN 需管理员权限，受运行环境限制未能自动化实测

## 版本策略

单一版本号 `0.1.0`，软件即内核。

---

## 内核原理（自研设计依据）

> 基于对现有内核源码的逐行研究整理。这是 clashgo 自研内核的教科书。

## 一、内核的本质：一条数据通路

任何代理内核都在做同一件事——**在连接建立之前，根据连接的"描述"决定把它送到哪里，然后双向转发数据**：

```
入站监听 → 握手解析 → 构造 Metadata → 规则匹配 → 选出站 → 拨号 → 统计包装 → 双向转发
   ↑            ↑            ↑              ↑          ↑         ↑           ↑
 HTTP/SOCKS5  协议字节    连接身份对象    规则引擎    DIRECT/SS  tracker    io.Copy
```

六个步骤就是所有内核的骨架，剩下的都是围绕它的增强。

## 二、核心设计思想：Metadata 是唯一枢纽

**规则引擎的输入不是"连接"，而是"连接的描述"（Metadata）**。原因：

1. 规则匹配发生在**拨号之前**——此时连接还没建立，只能依据地址/端口/进程等带外信息
2. 统一异构入站——HTTP 的 absolute-URI、SOCKS5 的 ATYP、TUN 的原始 IP 包，最终都归一成同一个 Metadata
3. 惰性计算——DNS 解析、进程查找做成闭包，只有 GEOIP/PROCESS 规则需要时才执行
4. 可序列化——直接进 API 展示"这次匹配依据"
5. 可重入——Rematch 出站可修改 metadata 后重新跑规则

精简版 Metadata 结构：
```go
type Metadata struct {
    Network   string  // tcp/udp
    Type      string  // http/socks5/tun
    SrcIP, DstIP netip.Addr
    SrcPort, DstPort uint16
    Host      string  // 域名（关键！规则主要匹配它）
    InName    string  // 入站名
}
```

## 三、两种内核架构哲学

| | 单体内核（Clash 系） | 组件化内核（sing-box 系） |
|---|---|---|
| 配置 | YAML：proxies / proxy-groups / rules 平铺 | JSON：inbounds / outbounds / route / dns，组件用 tag 连线 |
| 连接模型 | 中央 tunnel + 顺序遍历规则表 + 策略名查 map | Router 求值 route.rules → action → 目标 outbound 的 Dialer |
| 扩展点 | 所有出站实现大接口，分组是特殊 adapter | 每个组件独立，路由统一调度，接口更薄 |
| 热重载 | 支持 | 重建进程 |

**自研选择**：采用组件化的薄接口思想，但配置兼容 Clash YAML（复用现有订阅生态）。

## 四、最小接口定义

```go
// 出站：极薄，只有两个方法
type ProxyAdapter interface {
    Name() string
    DialContext(ctx context.Context, m *Metadata) (net.Conn, error)
}

// 规则：输入 metadata，输出是否命中 + 策略名
type Rule interface {
    Match(m *Metadata) (bool, string)
}

// 入站交给 dispatcher，不认识出站
type Dispatcher interface {
    Dispatch(ctx context.Context, conn net.Conn, m *Metadata) error
}
```

入站 → Dispatcher → Router（规则匹配）→ ProxyAdapter.DialContext → Relay。

## 五、入站实现要点

### SOCKS5（RFC 1928）
1. 方法协商：读 `VER(0x05) NMETHODS METHODS[]`，回 `{5,0}` 无认证 / `{5,2}` 用户名密码
2. 用户名密码子协商（RFC 1929）：读 VER ULEN user PLEN pass，回 `{1,0}`
3. 请求：读 `VER CMD RSV`，再读 `ATYP DST.ADDR DST.PORT`
   - ATYP: 0x01=IPv4(4B) / 0x03=域名(1B长度+N) / 0x04=IPv6(16B)
4. 回复：`{5,0,0} + BND.ADDR + BND.PORT`
5. UDP ASSOCIATE：TCP 连接保活，UDP 包格式 `RSV(2) FRAG(1) ATYP DST.ADDR DST.PORT DATA`

### HTTP
- `http.ReadRequest` 解析，目标是 absolute-URI 或 Host 头
- CONNECT 隧道：回 200 后按隧道转发；注意"peek 后回放"——预读的字节要补发出去

## 六、规则匹配数据结构

- **< 1000 条**：`map[string]policy` 精确匹配 + 后缀字符串判断 + `netip.Prefix` slice 线性扫描，够用
- **上千条 / geosite**：反向分段 trie（域名按 `.` 反转插入），O(标签数)
- **海量 IP**：二进制 trie（可用 `github.com/gaissmai/bart`）
- **必须保留"配置顺序优先"语义**——数据结构只是加速，不能改成"最长匹配优先"改变优先级

规则类型优先级：DOMAIN > DOMAIN-SUFFIX > DOMAIN-KEYWORD > IP-CIDR > MATCH(final)

## 七、流量统计：装饰器模式

```go
type Tracker struct {
    net.Conn              // 内嵌原始连接
    Upload, Download atomic.Int64
    Manager *Manager
}
func (t *Tracker) Read(b []byte) (int, error) {
    n, err := t.Conn.Read(b)
    t.Download.Add(int64(n))
    return n, err
}
func (t *Tracker) Write(b []byte) (int, error) {
    n, err := t.Conn.Write(b)
    t.Upload.Add(int64(n))
    return n, err
}
```
- Manager 用双缓冲算速率：每秒 `blip.Store(temp.Swap(0))`
- 连接关闭 = 从统计表移除（同一动作，避免幽灵连接）
- 显式注入 Manager，不用全局单例

## 八、自研分阶段路线图

| 阶段 | 内容 | 工期 | 可行性 |
|---|---|---|---|
| 0 | 骨架与数据契约（Metadata/ProxyAdapter/Rule 接口） | 1-2 天 | 极高 |
| 1 | HTTP + SOCKS5 TCP 入站 + DIRECT/REJECT + 双向转发 | 3-5 天 | 高 |
| 2 | 规则引擎 + Clash YAML 配置解析 | 3-5 天 | 高 |
| 3 | 流量统计 + 最小 REST（connections/traffic） | 3-5 天 | 中高 |
| 4 | UDP ASSOCIATE + NAT 表 + 超时回收 | 3-5 天 | 中 |
| 5 | SS 出站（AEAD，先 aes-256-gcm） | 5-10 天 | 中 |
| 6 | VMess 出站（协议细节多） | 5-10 天 | 中低 |
| 7 | TUN / sniffer / fake-ip DNS / providers | 按需 | 深水区 |

**关键原则**：
1. 以 Metadata 为唯一枢纽
2. 出站接口极薄，分组逻辑单独一层
3. 统计用装饰器 + 显式注入
4. 规则保留配置顺序语义
5. 先 TCP 后 UDP、先 DIRECT 后 SS、先本地配置后 providers

## 十、参考内核精读补充（逐行研究）

### 启动铁律：劫持系统 DNS
`main.go` 把 `net.DefaultResolver.Dial` 改成"打印所有 goroutine 栈并 os.Exit(2)"——**所有 DNS 必须走内核自己的 dns 模块**，否则 fake-ip 失效、DNS 泄漏。自研时至少要保证"出站解析用的 DNS ≠ 自己监听的 DNS"，避免环路。

### 关键实现细节（自研直接可抄）
- **mixed 端口分流**：`BufferedConn.Peek(1)` 看首字节，0x05=SOCKS5、0x04=SOCKS4、其它=HTTP。SOCKS4/5 首字节是固定版本号，HTTP 首字节是字母，天然区分。
- **SOCKS5 握手**：方法协商 `{5,0}` → 可选用户名密码(RFC1929) → 请求 `{VER,CMD,RSV,ATYP,ADDR,PORT}` → 回复 `{5,0,0}+BND.ADDR+BND.PORT`。ATYP: 1=IPv4(4B)/3=域名(1B长度+N)/4=IPv6(16B)。
- **HTTP 入站巧思**：普通 HTTP 用 `N.Pipe()` 内存管道，一端给 `http.Transport`，另一端交给 tunnel —— HTTP 和 CONNECT 复用同一套管线。
- **DOMAIN-SUFFIX 必须加前导点**：`strings.HasSuffix(domain, "."+suffix) || domain==suffix`，否则 `google.com` 会误命中 `oo.com`。
- **REJECT 返回假连接**（不返回 error）：`nopConn.Read` 立即 `io.EOF`，让流程正常走完，客户端看到连接立即关闭。
- **fake-ip 反查核心**：客户端连伪造 IP(198.18.x.x) → `FindHostByIP` 反查域名 → 清空 DstIP → 按域名匹配规则。反查失败则靠 sniffer 从 TLS SNI 兜底。
- **BufferedConn + Peek/回放**：sniffer 和 retry 都需要"预读字节后还能复用"，这是自备连接包装的原因。
- **UDP 按会话哈希到固定 worker**：`hash(key) % workers`，保证同会话有序；NAT 表按 key 缓存 PacketSender，超时回收。
- **流量统计装饰器**：`Tracker` 内嵌 Conn 重写 Read/Write 计数；`Manager` 双缓冲算速率（`blip.Store(temp.Swap(0))`）；连接关闭=从表移除。

### 包结构建议（8 个包）
```
mini-kernel/{constant, config, adapter/{inbound,outbound}, rules, dns, tunnel, listener}
```
**P0 主链路**：Metadata → mixed 入站(Peek分流+SOCKS5握手+HTTP CONNECT) → tunnel.match(first-match-wins) → DIRECT(net.Dial)/REJECT(nopConn) → 双向 io.Copy。
**P1**：BufferedConn+retry、流量统计、UDP ASSOCIATE+NAT 表。
**P2**：基础 DNS(miekg/dns)、fake-ip 池+反查（TUN 场景才需要；纯 SOCKS/HTTP 入站可完全跳过 DNS）。

## 九、版本策略

自研内核完成后，内核即软件的一部分，**统一版本号**（软件版本 = 内核版本），不再显示两套版本。

---

## 出站协议线格式说明

本文记录 `hysteria2Real` / `tuicReal` 的协议依据。所有格式均来自公开客户端源码，
本项目只读学习后**独立实现**，未引入任何外部依赖。

## Hysteria2

参考：`github.com/apernet/hysteria` `core/internal/protocol/{proxy.go,http.go}`，
`github.com/v2fly/v2ray-core` `proxy/hysteria2/protocol.go`。

### 握手与认证
- QUIC v1，TLS 1.3，ALPN `h3`
- HTTP/3 `POST https://hysteria/auth`（`:authority: hysteria`，`:path: /auth`）
- 请求头：`Hysteria-Auth: <密码>`、`Hysteria-CC-RX: <bps>`、`Hysteria-Padding: <任意>`
- 成功状态码：`233`；响应头含 `Hysteria-UDP: true/false`

### TCP 数据面（QUIC Stream）
```
varint(0x401)
varint(addrLen) + addr            // addr = "host:port" 字符串
varint(padLen) + padding          // 任意字节，服务端读后丢弃
--- 服务端响应 ---
status(1 byte, 0=ok) 
varint(msgLen) + msg
varint(padLen) + padding
--- 之后是原始 TCP 字节流 ---
```
常量：`FrameTypeTCPRequest = 0x401`，`MaxAddressLength = 2048`，`MaxPaddingLength = 4096`。

### UDP 数据面（QUIC DATAGRAM）
```
SessionID(4 BE) + PacketID(2 BE) + FragID(1) + FragCount(1)
+ varint(addrLen) + addr + data
```
真实 Hysteria2 在 DATAGRAM 之上还有可靠性/重组层（会话、分片、ACK）。
本项目当前实现**单分片无重传**路径，覆盖大多数常规 UDP 场景。

## TUIC v5

参考：`github.com/SagerNet/sing-quic` `tuic/{protocol.go,client.go,packet.go}`。

### 握手与认证
- QUIC v1 + TLS 1.3
- 打开一条**单向流**（unidirectional stream）写认证请求：
  ```
  Version(1 = 5) + CommandAuthenticate(1 = 0) + UUID(16) + Token(32)
  ```
- `Token = TLS-Exporter(label = UUID 原始 16 字节, context = password, length = 32)`
  （RFC 5705；Go 1.27 `tls.ConnectionState.ExportKeyingMaterial`）

### TCP 数据面（QUIC 双向流）
```
首包: Version(1) + CommandConnect(1) + Address + data
后续: 原始 TCP 字节流
```
Address 序列化：
```
type(1): 0x00=FQDN(1字节长度+域名), 0x01=IPv4(4), 0x02=IPv6(16), 0xff=空
port(2 BE)
```

### UDP 数据面（QUIC DATAGRAM）
```
Version(1) + CommandPacket(2) + SessionID(2 BE) + PacketID(2 BE)
+ FragTotal(1) + FragID(1) + DataLen(2 BE) + Address + data
```
心跳：`Version(1) + CommandHeartbeat(4)`（DATAGRAM，默认 10s）。

命令常量：
```
Authenticate=0, Connect=1, Packet=2, Dissociate=3, Heartbeat=4
```

## QUIC 协议栈

参考 RFC 9000（传输）、RFC 9001（加密）、RFC 9002（拥塞控制）、
RFC 9204（QPACK）、RFC 9114（HTTP/3）。

- 所有 AEAD / 头保护 / 帧 / 密钥派生均由 `internal/quicproto` 与
  `internal/http3proto` 纯标准库实现
- RFC 9001 Appendix A 官方向量逐字节匹配
- 本地 `tls.QUICServer` 握手 + echo 通过
- DATAGRAM 帧类型 `0x30`（带长度），RFC 9000 §19.4

## 诚实说明

- 上述格式为公开源码逆向/阅读所得，本项目实现已通过单元测试与本地 mock 验证。
- **未做真实公网服务端端到端实测**（环境无服务端凭据、UDP/853 出站被沙箱屏蔽）。
- 生产环境使用前请自行做真实服务端互通测试。

---

## 端到端验证指南

本协议栈的 QUIC/HTTP3/h2c 层已通过本地握手、RFC 官方向量与 279 个单元测试，
但**真实公网服务端**与**TUN 实机**需要在具备条件的环境里跑。本文把它们变成
可一键执行的验证流程。

---

## 证据层级（先理解现状）

| 层级 | 证据 | 状态 |
|---|---|---|
| 包格式/加密 | RFC 9001/9002/8439/9204 官方向量逐字节匹配 | ✅ 已通过 |
| 本地协议栈 | 标准库 `tls.QUICServer` 握手 + echo；110KB 大流量 | ✅ 已通过 |
| 数据面帧 | Hysteria2/TUIC 帧编解码 + mock 连接往返 | ✅ 已通过 |
| 用户态 TCP/IP | 46 测试 / 99.7% 覆盖 / `-race` 无竞态 | ✅ 已通过 |
| **第三方 QUIC 服务端** | 公网 HTTP/3 / DoQ | ⬜ 按本文步骤跑 |
| **真实代理服务端 + TUN 实机** | Hysteria2/TUIC + TAP 网卡 | ⬜ 按本文步骤跑 |

---

## 一、公网 QUIC 端到端（无需凭据，优先做这项）

### 1.1 一键验证：真实 HTTP/3 服务端

我们的 QUIC + HTTP/3 客户端直接访问 Cloudflare（真第三方 QUIC 实现）：

```bash
cd clashgo
go run ./cmd/verify quic
# 输出应包含：
#   [quic] TLS 1.3 handshake + QUIC OK
#   [quic] HTTP/3 response status = 200 (或 301/403 等合法状态码)
#   OK
```

自定义服务端：

```bash
go run ./cmd/verify quic cloudflare.com:443 cloudflare.com
go run ./cmd/verify quic www.google.com:443 www.google.com
```

** failing 时先排查**：本机是否有公网（用 `curl -I https://cloudflare.com` 验证 TCP、
用 `nslookup` 验证 UDP/53）。本机有公网时，若 QUIC dial 超时，通常是**实现 bug**
（例如 Initial 包超 MTU 被 IP 分片丢弃——本项目曾遇到并已修复），而非网络屏蔽。

### 1.2 验证 DoQ 集成路径

DoQ 用 UDP/853，若环境允许：

```bash
CLASHGO_DOQ_SERVER=dns.adguard-dns.com:853 \
  go test ./internal/minikernel/ -run TestLiveDoQViaDNS -v -count=1
```

或底层直连（与 quicproto 包的 `TestRealDoQ` 相同）：

```bash
DOQ_SERVER=dns.adguard-dns.com:853 \
  go test ./internal/quicproto/ -run TestRealDoQ -v -count=1
```

其它公共 DoQ：`dns.quad9.net:853`、`dns.cloudflare.com:853`。

### 1.3 用环境变量测试真实 Hysteria2 / TUIC 服务端

**准备服务端**（示例：Hysteria2，Docker）

```yaml
# hy2.yaml
listen: :443
acme:
  domains: [your.domain.example]
  email: you@example.com
auth:
  type: password
  password: change-me
tls:
  alpn: [h3]          # 必须与本内核一致
```

```bash
docker run -d --name hy2 -p 443:443/udp \
  -v $PWD/hy2.yaml:/etc/hysteria/config.yaml \
  apernet/hysteria:latest server
```

**TUIC v5** 可用 sing-box 起服务端（`type: tuic`，`version: 5`，TLS `alpn: [h3]`），
拿到 UUID 与密码。

**跑验证**：

```bash
# 一键 CLI
go run ./cmd/verify hy2  your.domain.example:443 change-me
go run ./cmd/verify tuic your.domain.example:443 <uuid> <password>

# 自签证书
CLASHGO_INSECURE=1 go run ./cmd/verify hy2 ...

# 指定测试目标（默认 www.google.com:80）
go run ./cmd/verify hy2 your.domain.example:443 change-me example.com:80

# 走测试框架（含认证 + TCP + UDP 三项）
CLASHGO_LIVE_HY2_ADDR=your.domain.example:443 \
CLASHGO_LIVE_HY2_PASSWORD=change-me \
  go test ./internal/minikernel/ -run 'TestLive(Hysteria2|UDP)' -v -count=1

CLASHGO_LIVE_TUIC_ADDR=your.domain.example:443 \
CLASHGO_LIVE_TUIC_UUID=<uuid> \
CLASHGO_LIVE_TUIC_PASSWORD=<password> \
  go test ./internal/minikernel/ -run TestLiveTUIC -v -count=1
```

可用环境变量：`CLASHGO_LIVE_HY2_SNI` / `CLASHGO_LIVE_TUIC_SNI`（SNI 与地址不同时）、
`CLASHGO_LIVE_TARGET`（TCP 目标，默认 `www.google.com:80`）、`CLASHGO_LIVE_INSECURE=1`。

判定标准：日志出现 `HTTP status: HTTP/1.1 200 OK`（或任意合法 HTTP 响应），
说明 QUIC 握手 + 认证 + TCP 数据面全链路打通。

---

## 二、TUN 实机验证

### 2.1 前置条件

1. Windows + **管理员权限**（打开 TAP 设备需要）
2. 已安装 **TAP-Windows 适配器**（本内核通过 `\\.\Global\{GUID}.tap` 打开，
   需要 TAP-Windows，不是 Wintun）
   - 安装方式：安装 OpenVPN 时会附带 TAP-Windows；或单独装
     `TAP-Windows` 驱动（tap-windows6 / TAP-Windows 9.x）
3. 适配器未被其它程序独占

### 2.2 检查前置条件

```bash
go run ./cmd/verify tun
```

成功输出：
```
[tun] TAP adapter OK: {GUID}
[tun] 适配器可打开。运行 CLASHGO_TUN_LIVE=1 ... 做实机收发验证。
OK
```

失败时按错误区分：
- `no TAP adapter found` → 没装 TAP-Windows 适配器
- `open TAP ...: 拒绝访问` → 没用管理员权限

### 2.3 实机收发验证

```bash
CLASHGO_TUN_LIVE=1 go test ./internal/minikernel/ -run TestLiveTUN -v -count=1
```

它会：探测 TAP → 打开并配置 198.18.0.1/16 → 注入一个 ICMP echo → 从适配器读回响应。
看到 `received ICMP reply from TAP` 或 `adapter I/O works` 即说明虚拟网卡收发正常。

### 2.4 整机流量验证（可选）

前置条件通过后，在管理界面开启 TUN，然后：

```powershell
ping 198.18.0.1          # 网关应可达
nslookup example.com     # DNS 应经内核
curl https://www.google.com
```

内核的 TUN 会自动配置路由（排除节点 IP 防环路）。注意关闭 TUN 后路由会被清理。

---

## 三、这些验证失败时怎么判断

- **协议层测试都过、只有公网失败** → 大概率是本机 UDP 出站被防火墙/沙箱屏蔽；
  用 UDP/53 的 DNS 查询做对照实验（能通说明 UDP 本身可用，问题在特定端口）。
- **公网 HTTP/3 握手失败但 DoQ 成功** → 检查服务端 ALPN 是否为 `h3`、TLS 证书链是否完整。
- **Hysteria2/TUIC 认证失败（status ≠ 233 / 无响应）** → 检查密码/UUID、
  `Hysteria-Auth` 与 TLS-Exporter 的 context（密码）是否一致；自签证书用 `CLASHGO_INSECURE=1`。
- **TAP 能打开但读不到包** → 检查 Windows 防火墙、适配器是否被重置；
  用 `netsh interface show interface` 确认适配器处于 connected 状态。

---

## 四、测试结果回写

验证通过后，建议把结果记入 `TODO.md` 的"未实测"段落（标注环境、日期、服务端类型），
让文档与实际状态保持一致。

---

## XTLS Vision / Reality 自研进展

> 借学习项目 Xray-core（v1.8.6 与 v26.3.27）本地搭服务端 + 抓日志定位。
> 所有新代码均在 `internal/vision`、`internal/reality`（cipher 动态化）。

## 已打通（实测）

- **Reality 握手**：cipher suite 动态化（AES-128/SHA-256、AES-256/SHA-384、ChaCha20），
  按服务端 ServerHello 协商的套件派生密钥。之前写死 AES-128 导致连 Xray 失败。
- **XTLS Vision 帧**：`[UUID16][cmd][contentLen2][paddingLen2][content][padding]`，
  command 0/1/2，随机 padding，首帧带 UUID。
- **VLESS header 分离**：header 直写底层（在 Vision 帧之前），VLESS 响应头由
  Vision conn 首次 Read 前透传 2 字节。
- **内层 HTTP 实测通过**：
  - 本地 Xray 1.8.6（VLESS+Reality+Vision）→ 本地 HTTP 服务 → `HTTP/1.0 200 OK`
  - 真实商业订阅节点 → `www.google.com:80` → `HTTP/1.1 200 OK`
  - ClashGo mixed 端口 `127.0.0.1:7897` → `http://example.com` → `HTTP 200`

## direct 模式（内层 HTTPS）—— 已打通

- 关键：服务端下行发 `commandPaddingDirect(0x02)` 时，direct 帧的 content
  就是内层 TLS 数据。正确处理：读 content → 读 padding 丢弃 → 取外层 TLS
  的 readBuf 残留接在后面 → 之后从裸 TCP 读。
- 之前失败原因：要么不读 content（数据丢失）、要么把 readBuf 全部当 content
  （混入 vision padding 乱码，报 `record with version 884b`）。
- 实测：`inner TLS: <nil>` + `HTTP/1.1 204 No Content`（gstatic 443）；
  mixed 端口 7897 代理 `https://www.gstatic.com/generate_204` 返回 204（0.88s）。

## 调试环境

- Xray 二进制：`C:/Users/xyh/go/bin/xray186.exe`（1.8.6）、`xray.exe`（26.3.27）
- 配置：`testserver/xray-config.json`（26）、`xray-config-old.json`（1.8.6）
- 测试 UUID：`b831381d-6324-4d53-ad4f-8cda48b30811`
- Reality 密钥对（本地测试）：private `uSYYR5g-...` / public `k0WQqsrh...`
- 本地 HTTP 测试目标：`python -m http.server 18080`

## 下一步（direct 模式）

参考 mihomo `transport/vless/vision/conn.go:142-179` 的 direct 读处理：
它用 unsafe 排空 tls.Conn 的 `input`/`rawInput` 内部缓冲后切 `netConn()`（裸 TCP）。
我们的 `tls13Conn` 是自写的，`readBuf` 等价于 `input`；需要在收到 direct 时：
1. 把 `readBuf` 残留 + direct 帧 content 按正确顺序合并交给上层
2. 之后从 `RawConn()`（裸 TCP）读，不再走外层 TLS 解密
3. 写侧对称：direct 后写裸 TCP

---

## 其他内核如何实现 Hysteria2/TUIC 与 TUN（研究记录）

> 研究来源：`C:/Users/xyh/go/pkg/mod/github.com/metacubex/mihomo@v1.19.34`
> 及 `sing-quic` / `sing-tun`（只读研究）。本项目零外部依赖，自研实现，
> 本文记录差距本质与可借鉴的实现路径。

## 一、Hysteria2 / TUIC 的 HTTP/3 数据面

### mihomo 的做法（依赖成熟库）

- 出站实现：`adapter/outbound/hysteria2.go`、`tuic.go`
- 依赖：
  - `github.com/metacubex/quic-go`（完整 QUIC v1 实现）
  - `github.com/metacubex/sing-quic/hysteria2`（Hysteria2 协议层）
  - **`github.com/metacubex/quic-go/http3.Transport`（成熟 HTTP/3 客户端）**

认证关键代码（`sing-quic/hysteria2/client.go: authenticateAndWrap`）：

```go
http3Transport := &http3.Transport{
    TLSClientConfig: c.tlsConfig,
    QUICConfig:      c.quicConfig,
    Dial: func(...) (*quic.Conn, error) { return quicConn, nil }, // 复用已握手的 QUIC 连接
}
request := &http.Request{
    Method: http.MethodPost,
    URL: &url.URL{Scheme: "https", Host: protocol.URLHost, Path: protocol.URLPath},
    Header: make(http.Header),
}
protocol.AuthRequestToHeader(request.Header, AuthRequest{Auth: password, Rx: receiveBPS})
response, err := http3Transport.RoundTrip(request.WithContext(ctx))
if response.StatusCode != 233 { return error }
```

即：quic-go 完成 QUIC 握手后，把连接注入 `http3.Transport`，用**标准 `net/http` 语义**发认证请求。
HTTP/3 的帧、QPACK、流管理、服务端推送等全部由 quic-go 处理。

### 数据面

认证通过后：
- TCP：每条连接开一条 QUIC stream，先写 TCPRequest 帧（varint 0x401 + addr + padding），再透传字节流
- UDP：QUIC DATAGRAM（`WritePacket`），带 Hysteria2 自己的 SessionID/PacketID/分片头
- 拥塞控制：Hysteria2 的 Brutal 拥塞控制（`congestion/brutal.go` + pacer），按声明带宽发包
- 全部基于 quic-go 的 stream/datagram API，流控/丢包恢复/密钥更新由 quic-go 负责

### 我们的差距（本质）

| 层 | mihomo | 我们（零依赖自研） |
|---|---|---|
| QUIC 传输 | quic-go（十年打磨，RFC 全套，海量服务端互通验证） | `internal/quicproto`（握手通 Cloudflare，数据面有未定位 bug） |
| HTTP/3 | quic-go/http3 + 标准 net/http | `internal/http3proto`（mock 验证，未与真实 quic-go H3 服务端互通） |
| 拥塞控制 | quic-go + Brutal | 简化 cwnd/PTO |
| DATAGRAM | quic-go | 自研 0x30 帧 |

我们卡住的点（请求发出后服务端不回）本质是**自研 QUIC/HTTP3 栈与 quic-go 服务端的某个协议细节不一致**，
不是网络问题（本机有公网，QUIC 握手已通 Cloudflare）。

### 可借鉴的修复路径（不引入依赖的前提下）

1. 用 quic-go 源码作为参照，逐个比对我们的：
   - 1-RTT 包的密钥派生与 header protection（尤其 key phase）
   - ACK 帧的 range 编码（已修：ACK Range Count = 额外 range 数）
   - 流控：我们宣告的 `initial_max_data` / 每流限制是否导致服务端拒绝
   - DATAGRAM 的 `max_datagram_frame_size` TP（Hysteria2 需要，我们没宣告）
2. 认证用真实 `http.Request` 语义对齐（方法/URL/Header 的 `Hysteria-Auth`/`Hysteria-CC-RX`/`Hysteria-Padding`）——我们已按此实现
3. 关键：Hysteria2 的 quic-go 配置里 `EnableDatagrams=true`，且 TLS ALPN=`h3`——我们 ALPN 对，但 TP 没宣告 datagram 支持

## 二、TUN 模式

### mihomo 的做法（sing-tun + gVisor）

- 实现：`listener/sing_tun/{server.go, prepare.go, server_windows.go}`
- 依赖：`github.com/metacubex/sing-tun` + `github.com/metacubex/gvisor`
- stack.go 支持三种模式：
  - `gvisor`：Google 生产级用户态 TCP/IP 栈（完整 TCP 状态机、拥塞控制、重组、ICMP）
  - `system`：交给系统栈（Windows 用 Wintun）
  - `mixed`：混合
- Windows：用 **Wintun** 驱动（`tun_windows.go`），不是 TAP-Windows；sing-tun 负责适配器创建、IP/路由配置、监控
- 路由：`component/iface` + sing-tun 的 monitor 监听网络变化自动重配

### 我们的差距

| 项 | mihomo | 我们 |
|---|---|---|
| 用户态栈 | gVisor（生产级，数百万行） | `internal/ipstack`（自研极简 IPv4/TCP/UDP/ICMP，46 测试） |
| 虚拟网卡驱动 | Wintun（高性能内核驱动） | TAP-Windows（旧的 TUN/TAP 驱动） |
| 路由/监控 | sing-tun monitor（网络变化自动重配） | 自研 setupRoutes，无自动监控 |
| 平台 | Win/mac/Linux/Android 全套 | 仅 Windows |

我们的 ipstack 能完成基本三次握手/echo/分片（单元测试），但：
- 没有完整 TCP 状态机（TIME_WAIT、重传、乱序、窗口管理）
- 没有真实网卡驱动集成验证（本机无管理员 + TAP 适配器）
- 不具备生产级栈的健壮性

### 可借鉴的路径（不引入依赖）

1. 参考 gVisor 的 TCP 状态机设计，补齐我们 ipstack 的：
   - 接收窗口与流量控制
   - 重传与 RTO
   - FIN/RST 完整状态转换
2. Windows 侧从 TAP 切换到 Wintun（需要适配其 DLL 接口）——纯标准库可用 syscall 调用 Wintun DLL
3. 加网络变化监控：监听 `net.Interfaces()` 变化，自动重配路由（类似 ssid 自动化）

## 排查进展（已排除/已确认）

- ✅ **本机有公网**：curl cloudflare 301、纯 UDP DNS 查询 8.8.8.8 正常（之前误判为"沙箱屏蔽"）
- ✅ **QUIC 握手与 Cloudflare 成功**：修了 Initial 包超 MTU（ClientHello 拆包）、Initial DCID 误用、重传风暴等 bug 后，5/5 握手成功
- ✅ **ACK 帧编码修复**：RFC 9000 §19.3.1 的 ACK Range Count 是"额外" range 数（我们之前写成总数），已修 + 5 个测试
- ✅ **QPACK 编码验证通过**：把我们的 `EncodeFieldSection` 字节喂给 quic-go 实际使用的 `metacubex/qpack v0.6.0` 解码器，成功解出 `:method/:scheme/:authority/:path`——**H3 头编码没问题**
- ✅ **HTTP/3 数据面打通**：读 quic-go 源码 + 本地真实 quic-go H3 服务端复现，拿到 qlog 原因短语 "invalid first ACK range"（0x7 实为 FRAME_ENCODING_ERROR，不是 TP error），定位并修复 5 个 bug：
  1. ACK 帧 off-by-one：First ACK Range/Gap/Range Length 的 RFC 语义（`largest-smallest`）
  2. 短首包 pnOffset = `1+len(c.scid)`（不是 `c.dcid`）
  3. 握手完成清 sendQueue 时回退拥塞状态（cwnd/inflight 卡死导致 STREAM 发不出去）
  4. 不再吞掉握手后的 CLOSE（之前把服务端拒绝信号吞了）
  5. DATAGRAM LEN 位修正 + max_datagram_frame_size TP + idle timeout 30s
  - 修复后 `go run ./cmd/verify quic` 连续 **5/5 成功**拿到真实 Cloudflare 的 HTTP/3 响应
- ✅ **TP 方向确认无问题**：quic-go qlog 显示我们的客户端 TP 被完整正确解析接受（ISCID/max_udp_payload_size/各流控值全部正确）

## 三、结论

**其他 Clash 能实现这两块，靠的是成熟库**：
- QUIC/HTTP3 → quic-go + http3（我们零依赖自研，所以卡在协议细节）
- TUN → sing-tun + gVisor（生产级用户态栈 + Wintun 驱动）

我们的"未打通"不是能力缺失，而是**用纯标准库自研替代大型成熟库的代价**：
- QUIC 握手已通，数据面 bug 可继续按 quic-go 源码逐项比对修复
- TUN 代码完成但需要管理员+TAP 环境实机验证，且栈的健壮性不如 gVisor

这两项若要达到生产级，路径只有两条：
1. 继续自研（按本文的对照表逐项补齐，工作量巨大）
2. 引入依赖（quic-go / sing-tun），但违背"零外部依赖"的初始目标
