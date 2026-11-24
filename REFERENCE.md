# 参考资料与待办（研究记录）

---

## 后端参考：Clash Verge Rev 架构

> 来源：Clash Verge Rev 的 `src-tauri/src`（Rust + Tauri，v2.6.0，只读研究）。
> 用于与本项目纯 Go 后端的实现对照。

## 分层

```
前端 (React) ──invoke(~90 命令)──> cmd/ 命令层 ──> feat/ 业务编排 ──> config/ + core/
                                         │
                                         └──> tauri-plugin-mihomo ──本地 socket/pipe──> mihomo 内核
前端 ──mihomo-api(HTTP/WS 代理)──> 内核（高频数据：proxies/connections/traffic）
后端 ──emit 事件──> 前端 services/bus（Refresh/Notice/ProfileChanged/RunStateChanged...）
```

- **cmd/**：Tauri 命令薄封装，统一错误码 `CommandFailure { code, detail, operation }`
- **feat/**：业务编排（patch 事务/效果注册表/订阅/备份/解锁）
- **config/**：IVerge/IProfiles/IClashTemp/IRuntime 四类配置 + Draft 草稿 + 全局写锁
- **core/**：机制层（CoreManager/proxy_control/service/hotkey/timer/updater/backup/validate...）

## 关键命令（cmd/）

| 文件 | 主要命令 |
|---|---|
| clash.rs | get_clash_info / patch_clash_config / patch_clash_mode / restart_core / change_clash_core / upgrade_clash_core / test_delay / DNS 配置组 / get_clash_logs |
| profile.rs | get_profiles / import_profile / update_profile / delete_profile / patch_profiles_config(切换) / reorder / enhance_profiles / read_profile_file / get_next_update_time |
| proxy.rs | switch_proxy_node / record_selected_node / get_proxy_view |
| verge.rs | get_verge_config / patch_verge_config |
| backup.rs / webdav.rs | 本地/WebDAV 备份的 create/list/delete/restore/export |
| runtime.rs | get_runtime_config / get_runtime_yaml / get_runtime_logs / 代理链配置 |
| service.rs | install/uninstall/reinstall/repair_service（Windows 提权） |
| system.rs | get_runtime_state / get_pending_failures |
| app.rs | open_*_dir / exit/restart_app / install_update / devtools |
| listener.rs | probe_listener / save_proxy_ports（端口冲突探测） |
| save_profile.rs | save_profile_file（先内核校验，失败回滚，成功触发自动备份） |
| media_unlock_checker | get_unlock_items / check_media_unlock / check_media_unlock_item |

## 核心机制（core/）

- **CoreManager**：内核生命周期。`RunningMode::{Sidecar, Service, NotRunning}`
  - Sidecar：spawn `<core> -d <appdir> -f <yaml> -ext-ctl-pipe/unix <ipc>`，Job Object（Win）保证退出杀进程，轮询 `/version` 就绪检测
  - Service：打包 RuntimeBundle（YAML+geo+providers）经 IPC 交给提权服务启动，owner monitor + sidecar→service 交接（120s）
  - 配置热更新：`PUT /configs?force=true`，失败则重启内核
- **proxy_control / sysopt**：系统代理总控，失败分类（PrivilegeRequired/CoreNotReady/...），guard 每 30s 重写，连续 3 次失败停止；PAC 支持
- **timer**：DelayQueue 定时更新订阅（remote + allow-auto-update + interval>0，首次按 updated+interval，过期立即）
- **hotkey**：全局热键（开关面板/模式/系统代理/TUN/轻量模式/重启激活/退出），非全局模式仅窗口聚焦时生效
- **backup / auto_backup**：zip 备份（移除 WebDAV 凭据），定时(1-168h)+变更触发，保留 20 份
- **updater**：镜像回退下载、签名校验、后台 24h 静默检查、Windows `/LANG` 抑制 NSIS 对话框
- **validate**：YAML 用内核 `mihomo -t` 真校验；脚本用 Boa 解析要求 main；带指纹去重避免重复校验
- **lightweight**：Normal→In→Exiting 状态机，定时无操作进入轻量模式
- **network_watch**（macOS）/ **owner_identity**（Windows SID/token）/ **win_uwp**（UWP loopback）：平台特有

## 配置层（config/）

- **IProfiles / PrfItem**：订阅项模型，字段含 uid/type/name/url/option(UA/代理/间隔/超时/危险证书/自动更新)/extra(流量/到期)；节点选择恢复带 generation 防旧异步覆盖
- **IVerge**：~100 字段应用设置（含 WebDAV 凭据 `serialize_encrypted` 加密）
- **encrypt**：AES-256-GCM + 随机 nonce + Base64，密钥为应用目录 `.encryption_key`
- **snapshot**：config.yaml/verge.yaml/clash-verge.yaml 快照，用于事务回滚
- **port.rs / mixed_port.rs**：启动时端口占用自动回退；MixedPort 优先级 会话回退 > 用户选择 > merge 配置
- **runtime**：IRuntime 只更新白名单字段（allow-lan/ipv6/log-level/tun/tunnels）

## 本项目对照（纯 Go）

| Verge 后端 | 本项目实现 | 状态 |
|---|---|---|
| cmd/clash.rs（内核控制） | internal/kernel + internal/controller | ✅ |
| cmd/profile.rs（订阅管理） | internal/profile | ✅ |
| cmd/proxy.rs（代理视图） | internal/minikernel/api.go + delay.go + groups.go | ✅ |
| core/timer.rs（订阅定时更新） | internal/profile/timer.go | ✅ 已补 |
| config/encrypt.rs | internal/backup + internal/profile（AES-GCM） | ✅ |
| config/snapshot.rs | internal/snapshot | ✅ |
| config/port.rs（端口回退） | internal/portfallback | ✅ |
| core/autostart / hotkey / backup / updater | internal/autostart / ui/hotkeys.go / internal/backup / ui/autoupdate.go | ✅ |
| core/service（Windows 服务） | internal/service | ✅（进程内内核，无需 sidecar/交接） |
| tauri-plugin-mihomo（内核 API） | internal/controller + internal/minikernel + internal/webapi | ✅（进程内 REST/WS，等价且更简单） |
| core/network_watch（macOS） | internal/ssid | ✅ |
| core/win_uwp / owner_identity（Windows 特有复杂权限） | — | 架构差异：进程内内核不需要 |

---

## UI 参考：Clash Verge Rev 信息架构

> 来源：Clash Verge Rev v2.6.0 源码（只读研究），用于本项目的界面对齐。
> 前端为 React + MUI + Tauri，本项目用纯 Go (mygo, immediate mode) 实现等价布局。

## 全局框架

- 布局：侧边栏 + 内容区；自定义标题栏（拖拽区 + 最小化/最大化/关闭）
- 全局浮层：通知、加载遮罩、错误边界

## 侧边栏（layout-sidebar.tsx）

- 顶部：Logo + 更新按钮
- 导航列表 8 项（可拖拽排序、可收起、右键菜单）：
  首页 `/`、代理 `/proxies`、订阅 `/profile`、连接 `/connections`、
  规则 `/rules`、日志 `/logs`、测试(解锁) `/unlock`、设置 `/settings`
- 底部：实时流量图（上传/下载/内存）

## 首页（9 张卡片，Grid 12 列，除流量统计占 12 列外其余各占 6 列）

1. **订阅卡**：订阅名+主页外链、来自、更新时间、已用/总量、到期、进度条；空状态"导入 订阅"
2. **当前节点卡**（最复杂）：信号强度图标、延迟测试/排序/跳转按钮、当前节点名+类型+模式 Chip+特性 Chip+延迟 Chip、规则入口/代理组下拉、代理链
3. **网络设置卡**：系统代理 / 虚拟网卡模式 两个 Tab + 描述条 + 对应开关
4. **代理模式卡**：规则 / 全局 / 直连 三个按钮 + 描述条
5. **流量统计卡**（12 列）：流量图 + 上传速度/下载速度/活跃连接/上传量/下载量/内核占用
6. **网站测试卡**：测试全部/新建按钮、Apple/GitHub/Google/YouTube 测试项网格、延迟状态
7. **IP 信息卡**：国旗+国家、IP（默认隐藏）、自治域、服务商/组织/位置/时区、自动刷新 Switch
8. **Clash 信息卡**：内核版本/系统代理地址/混合端口/运行时间/规则数 + 重启内核按钮
9. **系统信息卡**：操作系统/开机自启/运行模式/最后检查更新/Verge 版本

首页头部 3 个 IconButton：轻量模式、使用手册、首页设置（9 卡开关对话框）。

## 代理页（proxies.tsx）

- 头部：代理集合按钮、模式按钮组（规则/全局/直连）、链式代理开关（含确认框）
- 列表：吸顶组头 + 6 个工具按钮（定位当前/延迟测试/排序/自定义测试链接/显示隐藏/搜索）+
  节点行（节点名+类型+特性标签+延迟控件+固定节点📌）+ 字母导航器
- 链式模式：入口/出口节点、点选加入链
- 代理集合弹窗：provider 名+节点数+更新按钮+流量进度

## 订阅页（profiles.tsx）

- 头部：批量操作/更新全部/运行时配置/重新激活/强制刷新
- 导入区：URL 输入框（粘贴/清空）+ 导入 + 新建；支持 YAML 拖放
- 订阅卡片网格（可拖拽排序）：名称+更新按钮+描述+更新时间+流量进度+到期
- 右键菜单：使用/编辑信息/编辑文件/编辑规则/编辑代理/编辑代理组/扩展覆写/扩展脚本/打开文件/更新/删除
- 底部：全局扩展覆写配置(Merge) + 全局扩展脚本(Script)

## 连接页（connections.tsx）

- 头部：下载/上传总量、列表/表格视图切换、关闭全部
- 筛选栏：活跃/已关闭、排序（列表模式）、All/TCP/UDP、搜索、列设置（表格模式）
- 表格视图 12 列（可排序/调宽/显隐/持久化）+ 行详情 Snackbar + 关闭连接
- 列表视图：host + Tag 胶囊 + 关闭按钮
- 已关闭模式：清除按钮

## 规则页（rules.tsx）

- 头部：规则集合按钮；搜索框（匹配 payload）
- 列表：行号 / payload / type / proxy（按策略着色）+ 回顶按钮

## 日志页（logs.tsx）

- 头部：暂停/继续、正序/倒序、清除
- 筛选：等级 ALL/DEBUG/INFO/WARN/ERROR + 搜索
- 列表：时间 + 等级胶囊 + 内容（搜索高亮）+ 自动滚动

## 测试页（unlock.tsx）

- 头部：测试全部
- 3 列卡片网格：服务名 + 单项重测 + 状态 Chip + 地区 Chip + 检测时间
- 状态：Pending/Yes/No/Failed/Risky/Completed/... ；localStorage 持久化

## 设置页（settings.tsx）

- 搜索设置框 + 头部：手册/Telegram/GitHub
- 两列四分组：
  - 左：系统设置（TUN/系统代理/自启/静默启动）、Clash 设置（allow-lan/DNS 覆写/IPv6/统一延迟/日志等级/端口/外部控制/网页界面/内核/UWP/GeoData/隧道）
  - 右：Verge 基础（语言/主题/托盘事件/复制环境变量/启动页面/启动脚本/主题/界面/杂项/热键）、Verge 高级（备份/当前配置/配置目录/内核目录/日志目录/检查更新/开发者工具/轻量模式/退出/诊断信息/版本）
- 各设置项通过 18+ 个模态窗口编辑（主题/界面/杂项/热键/备份/端口/控制器/CORS/WebUI/DNS/TUN/系统代理/隧道/更新等）

## 本项目当前对齐状态

- [x] 侧边栏改为 8 项标准导航 + 底部流量图
- [x] 默认启动页改为首页
- [x] 首页新增代理模式卡、网络设置卡（系统代理/TUN）
- [x] 连接页新增 All/TCP/UDP 筛选 + 关闭全部按钮
- [x] 日志页新增暂停/继续 + 正序/倒序
- [x] 页面标题对齐（配置→订阅、媒体解锁→测试）
- [ ] 首页其余卡片（当前节点卡下拉、网站测试卡、IP/Clash/系统信息卡）按 Verge 细化
- [ ] 订阅页右键菜单、代理页链式模式、连接页表格视图、设置页模态窗口等深度功能

## 后端对照

Clash Verge 用 `tauri-plugin-mihomo-api` 与内核通信（HTTP REST + WebSocket + IPC）。
本项目用进程内 REST/WebSocket 控制接口（`internal/controller` + `internal/minikernel`），
能力等价：version/configs/proxies/rules/connections/traffic/logs/dns-query + WS 流。

后端功能域逐项对照（详见 `BACKEND_REFERENCE.md`）：订阅导入/更新/定时/切换/节点持久化、
配置增强管线、内核生命周期、系统代理/PAC/守护、TUN、代理节点视图、备份/WebDAV、
热键、托盘、自启、轻量模式、日志、更新、DNS 覆盖、解锁检测、Deep Link、单例、服务模式——
全部有对应实现。其中订阅定时自动更新由 `internal/profile/timer.go` 实现
（对齐 Verge 的 `core/timer.rs`：只调度 remote + allow-auto-update + interval>0，
首次按 `updated + interval` 触发，过期立即更新，更新前后回调通知）。

---

## TODO 清单进度

> 目标：除 mygo 外零外部依赖，全部纯标准库实现。
> 已达成：go.mod 仅 mygo（+ 其 5 个传递依赖），58 个外部依赖已清零。
> 全量测试：**279 passed in 65 packages**；关键包 `-race` 全过；`go vet ./...` 干净。

## 已完成 ✅

### 2. 出站协议
- [x] DIRECT / REJECT / Shadowsocks / ShadowsocksR / VMess / VLESS / Trojan
- [x] Shadowsocks chacha20 / xchacha20 + UDP（14 测试）
- [x] WireGuard 出站（Noise_IKpsk2 框架，7 测试）
- [x] **Hysteria2 真协议**（internal/minikernel/hysteria2_real.go）：
  - QUIC(ALPN h3) + HTTP/3 认证（POST https://hysteria/auth，状态 233）
  - TCP 数据面按真实 `FrameTypeTCPRequest(0x401)` + TCPResponse 帧格式实现
  - UDP 数据面按 `SessionID/PacketID/FragID/FragCount + addr + data` 走 QUIC DATAGRAM
  - 协议依据见 `PROTOCOLS.md`（来自 apernet/hysteria 与 v2ray-core 源码）
- [x] **TUIC v5 真协议**（internal/minikernel/tuic_real.go）：
  - TLS-Exporter(UUID 原始 16 字节, password, 32) 认证（单向流 `[5][0][uuid][ekm]`）
  - TCP Connect 首包 `[5][1][Address][data]` + 原始字节流
  - UDP DATAGRAM `[5][2][sid][pid][fragTotal][fragID][dataLen][Address][data]` + 心跳
  - 协议依据见 `PROTOCOLS.md`（来自 sing-quic/tuic 源码）

### 3. 规则引擎
- [x] DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / MATCH
- [x] DST-PORT / SRC-PORT / NETWORK / IN-TYPE / PROCESS-NAME
- [x] GEOIP / GEOSITE（CN 471 段 + 多地区真实 CIDR / 域名分类）
- [x] RULE-SET（文件/远程加载）；>200 纯域名规则自动启用 DomainTrie

### 5. DNS
- [x] UDP / TCP DNS 服务 + fake-ip + hosts + 惰性解析
- [x] DoH / DoT / **DoQ**（自研真 QUIC，dns.go 的 `doq://` nameserver）
- [x] fallback 防污染 + redir-host 基础

### 7. UDP / NAT
- [x] SOCKS5 UDP ASSOCIATE + NAT 会话表 + Full-Cone + 超时回收
- [x] Hysteria2 / TUIC UDP 出站（QUIC DATAGRAM）

### 8. 配置 / 热重载
- [x] 自研 YAML（tag/锚点/块标量）+ 语义校验
- [x] 热重载不中断长连接（atomic 配置快照）

### 9. 传输层
- [x] gRPC 传输：标准库 HTTPS + HTTP/2 ALPN（真实双向流 echo 测试通过）
- [x] gRPC 明文 h2c（internal/grpcproto：prior-knowledge + HPACK 静态/动态表 + Huffman 解码 + 流控 + trailers，21 测试）
- [x] WebSocket 传输

### 真 QUIC / HTTP3（全部纯标准库自研）
- [x] QUIC v1 协议栈（internal/quicproto，29 测试）：
  - Initial 密钥/头保护/帧/ACK/握手状态机（RFC 9001 官方向量逐字节匹配）
  - **DATAGRAM 帧 0x30/0x31** + 接收队列 + ctx 取消
  - **ChaCha20-Poly1305**（RFC 8439 全套向量 + RFC 9001 A.5 向量）
  - **拥塞控制 + PTO**（RTT 采样、cwnd、慢启动/拥塞避免、110KB 大流量测试）
  - **密钥更新**（key phase 翻转、三代密钥兼容）
  - **Retry**（RFC 9001 A.4 官方向量 + 完整性 tag 校验）
  - **版本协商**
  - TLS EKM 导出（TUIC v5 认证用）
- [x] HTTP/3 + QPACK（internal/http3proto：RFC 9204 静态表 99 项 + RFC 7541 Huffman 257 项；15 测试）

### 其它
- [x] TUN 纯标准库实现（Windows TAP + syscall + 用户态 IPv4/TCP/UDP/ICMP 协议栈）
- [x] **TUN 协议栈测试**（internal/ipstack：46 测试、99.7% 覆盖率；含 IPv4/校验和/ICMP/UDP/TCP 握手/分片/pipeConn/Close）
  - 修复了 `handleTCP` 中"先唤醒上层再更新 rcvNxt"的真实竞态，以及 `SetWriteDeadline` 未生效的 bug
- [x] 防环路（节点 IP 排除）+ 系统代理守卫
- [x] Sniffer（TLS SNI / HTTP Host）
- [x] 重建安装包 dist/ClashGo-Setup.exe（28MB，GUI 无控制台）

## 未实测 / 环境限制 ⚠️

这两项是**环境限制**，代码层面已做到最大可验证性（本地 TLS 握手 echo + RFC 官方向量 + mock 数据面往返 + 高覆盖单元测试）。已把它们做成**可执行验证**——见 `VERIFY.md`：

- [x] **公网 QUIC 握手**：已与真实 Cloudflare 完成 TLS 1.3 + QUIC 握手（5/5 稳定）。之前连不上是代码 bug：ClientHello 1508 字节塞进单个 UDP 数据报超 MTU 被 IP 分片丢弃（已修为多包分片）。本机有公网（curl/UDP DNS 验证），并非网络屏蔽。
- [x] 修复了握手期的多个真实 bug：Initial 包 DCID 误用服务端 SCID、握手完成后残留 Initial/Handshake 包、CRYPTO 重传分片、ACK 未清理已确认帧导致的重传风暴、延迟到达的过期 CLOSE 误杀连接。
- [x] **公网 HTTP/3 数据面打通**：通过读 quic-go 源码 + 本地真实 quic-go H3 服务端复现，定位并修复 5 个协议 bug，之后 `go run ./cmd/verify quic` 连续 5/5 成功拿到真实 Cloudflare 的 HTTP/3 响应。详见 `HOW_OTHERS_DO_IT.md`。修复项：
  1. ACK 帧 off-by-one（0x7 FRAME_ENCODING_ERROR "invalid first ACK range"）：First ACK Range / Gap / Range Length 的 RFC 语义（`largest-smallest`）
  2. 短首包 pnOffset 应为 `1+len(c.scid)`（服务端短首包 DCID = 我们的 SCID，非 c.dcid）
  3. 握手完成清 sendQueue 时回退拥塞状态（否则 cwnd 卡最小、STREAM 帧发不出去）
  4. 不再吞掉握手后的 CLOSE（之前把服务端拒绝信号吞了，误以为连接活着）
  5. DATAGRAM 帧 LEN 位修正（0x30=无长度/0x31=有长度）+ 声明 max_datagram_frame_size TP + idle timeout 改 30s
- [x] **VLESS Reality + XTLS Vision 完全打通**：借 Xray-core 源码精确定位并修复：
  1. Reality cipher suite 动态化（之前写死 AES-128/SHA-256，而 Xray 用伪装站点协商的套件）
  2. Vision 帧编解码（UUID padding 头 + 三个命令 + 随机 padding）
  3. VLESS header 与 Vision 帧分离、响应头透传
  4. **direct 模式**（内层 HTTPS 时服务端切裸 TCP）：按 mihomo 的行为读 direct 帧 content + 外层 TLS 残留后切裸 TCP
  - 实测：本地 Xray 1.8.6 + 真实商业订阅节点，HTTP 200 / HTTPS 204（gstatic），mixed 端口 7897 代理全链路可用。详见 `VISION_STATUS.md`。
- [ ] Hysteria2/TUIC 服务端端到端：`CLASHGO_LIVE_HY2_*` / `CLASHGO_LIVE_TUIC_*` 驱动的 live 测试（QUIC+HTTP3 数据面已通，待真实服务端凭据实测）。
- [ ] **TUN 实机**：`go run ./cmd/verify tun` 检查前置条件；`CLASHGO_TUN_LIVE=1 go test ./internal/minikernel/ -run TestLiveTUN -v` 做实机收发。本环境非管理员、无 TAP 适配器，需在管理员权限 + 已装 TAP-Windows 的 Windows 上跑。

## 关于"硬限制"的更正

之前认为真 QUIC / 明文 h2c 是标准库的"硬限制"——**均已推翻**：
- Go 1.27 标准库 `crypto/tls` 提供 `tls.QUICConn`（QUIC TLS 1.3 事件循环），包层全部自研并通过 RFC 官方向量。
- 明文 h2c 通过自研 HTTP/2 帧层 + HPACK 实现，不依赖 net/http 的 h2c 支持。
- ChaCha20-Poly1305 标准库无导出 AEAD，纯标准库手写实现（RFC 8439 向量验证）。

现存的只是**环境限制导致的未实测项**（TUN 实机、Hysteria2/TUIC 真实服务端凭据），不再是标准库能力限制或协议栈 bug。公网 QUIC + HTTP/3 数据面已与真实 Cloudflare 互通验证通过。

## 已删除的功能（因零依赖）

- JS/Lua 脚本附件（goja/gopher-lua）—— 纯 Go 不需要脚本引擎
- 第三方内核（mihomo）—— 全面替换为自研内核
