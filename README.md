# ClashGo

用 **纯 Go** 实现的桌面代理客户端：**自研内核**与 **MyGo 原生 UI** 都编译进同一个二进制，无 JavaScript、无 WebView、无外部内核进程、无第三方内核依赖。

```
┌──────────────────────────────────────┐
│  ClashGo (single Go binary)          │
│                                      │
│  MyGo native UI  ←→  自研 Go 内核     │
│       │                  │           │
│   ui.View()        REST + WebSocket  │
└──────────────────────────────────────┘
```

## 核心能力（全部自研）

- **多协议入站**：Mixed 端口同时支持 SOCKS5（CONNECT / UDP ASSOCIATE）与 HTTP（CONNECT / 普通代理）；TUN 虚拟网卡（纯标准库 TAP + 用户态协议栈）
- **规则引擎**：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / MATCH / 端口 / 网络 / 进程 / GEOIP / GEOSITE / RULE-SET，配置顺序优先（first-match-wins），大量域名规则用 Trie 加速
- **出站协议**：DIRECT / REJECT / Shadowsocks / ShadowsocksR / VMess / VLESS / Trojan / WireGuard / Hysteria2 / TUIC，支持 TCP、TLS、WebSocket、gRPC（含 h2c）传输
- **真 QUIC 协议栈**：纯标准库实现 QUIC v1（Initial 密钥/头保护/帧/ACK/握手状态机、DATAGRAM、ChaCha20-Poly1305、拥塞控制/PTO、密钥更新、Retry/版本协商），通过 RFC 9001/8439 官方向量，本地 TLS 1.3 握手 echo 通过
- **DNS**：内置 DNS + hosts + fake-ip 反查 + DoH / DoT / DoQ（自研 QUIC）+ fallback 防污染 + 惰性解析
- **代理组**：手动选择（Selector）/ 自动测速（URLTest）/ 故障转移（Fallback）/ 负载均衡（LoadBalance），延迟测试并发执行
- **TUN 模式**：基于用户态协议栈的虚拟网卡，接管不支持系统代理的程序流量（需管理员权限）
- **流量统计**：装饰器模式逐连接计数，REST + WebSocket 实时上报
- **控制接口**：Clash 兼容的 REST API 与 WebSocket 流（version/configs/proxies/rules/connections/traffic/logs/dns-query）

## 界面

默认中文界面。五个主导航：首页 / 代理 / 配置 / 连接 / 设置；规则、日志、媒体解锁、DNS 查询、请求记录等工具入口集中在设置页。

- **首页**：一键开关系统代理的大状态卡、TUN 开关、当前节点/订阅流量/活跃连接摘要、流量曲线、出口 IP、代理组概览
- **代理页**：模式切换（规则/全局，直连已合并到"关闭系统代理"）、节点搜索、延迟测试、分组折叠、按地区建组
- **配置页**：订阅导入/批量导入、更新、扩展管线（merge / seq / script / overlay）、YAML 编辑器
- **设置页**：端口、系统代理、代理守护、DNS、TUN、备份（本地/WebDAV）、开机自启、PAC、热键、外观等

## 可靠性

系统代理守卫（防篡改）、端口回退、配置语义校验与快照回滚、TUN 降级、BootGuard 崩溃恢复、退出自动清代理、单实例锁。

## 已知限制（诚实说明）

**可用（已充分验证）**：Shadowsocks / ShadowsocksR / VMess / VLESS（含 Reality + XTLS Vision）/ Trojan / WireGuard 出站，规则引擎、DNS（DoH/DoT/DoQ）、代理组、TUN 代码、REST/WS 控制接口。VLESS-Reality+Vision 已在真实商业订阅节点上实测 HTTP 200 / HTTPS 204（见 `VISION_STATUS.md`）。全量 300 个测试通过（e2e 需 `CLASHGO_E2E=1` 显式运行），关键包 `-race` 通过，`go vet` 干净。

**实验性（协议栈已打通，待真实服务端凭据实测）**：
- **Hysteria2 / TUIC**：协议帧按真实格式实现（认证、TCP 请求/响应、UDP DATAGRAM，见 `PROTOCOLS.md`）。自研 QUIC + HTTP/3 已与公网 Cloudflare 完成握手 + HTTP/3 GET 请求/响应（5/5 成功，通过读 quic-go 源码修复 5 个协议 bug，详见 `HOW_OTHERS_DO_IT.md`）。Hysteria2/TUIC 服务端端到端待真实凭据实测。
- **TUN 实机**：需管理员权限 + TAP-Windows 适配器，本环境不满足；用户态 IPv4/TCP/UDP/ICMP 协议栈有 46 个单元测试、99.7% 覆盖率作为代码级验证，但未实机跑过。

公网 QUIC / TUN 实机验证已做成可执行流程：`go run ./cmd/verify quic`、`go run ./cmd/verify tun` 及环境变量驱动的 live 测试，详见 `VERIFY.md`。当前版本定位为自研内核的学习/实验成品，生产环境使用前请自行做真实服务端互通测试。

## 构建

需要 **Go 1.27+**。Windows 原生 UI 只需 Go，无 cgo、无需 WebView2。

```bash
cd clashgo
go build -o clashgo.exe .
```

测试：

```bash
go test ./...
```

一键构建安装包（无黑窗口、覆盖安装、可选安装位置与快捷方式）：

```bash
bash build-setup.sh
# 产物：dist/ClashGo-Setup.exe
```

## 版本

软件版本即内核版本，统一为 `0.1.0`。自研内核是本项目的一部分，不再单独维护版本号。

## 许可

本项目为学习/实验性质。UI 依赖 [MyGo](https://github.com/egoist/mygo)。

---

## 文档导航

- `DEVELOPMENT.md` — 架构、内核原理、协议格式、验证流程、Vision 进展、他人实现研究
- `REFERENCE.md` — 后端/UI 参考资料、TODO 清单
