# ClashRS 参考：Rust 版实现经验与 Go 版落地情况

本文记录 ClashRS（Rust 自研内核 + Flutter 桌面端）实现过程中沉淀的可复用经验，
以及这些经验在 ClashGo（纯 Go 内核 + MyGo 原生 UI）中的落地情况。

ClashRS 已作为独立公开仓库发布（`clashrs`），代码不再保留在本仓库。
本文只保留**设计与实现层面**的结论，不含任何凭据、本机路径或真实节点信息。

---

## 一、为什么最终回到 Go

| 维度 | ClashGo（Go） | ClashRS（Rust） |
|---|---|---|
| 业务逻辑 | 标准库足够，无第三方依赖 | 需要 `aes-gcm` / `x25519-dalek` 等 crate |
| 内核开发速度 | 编译秒级，改一行立刻验证 | 编译分钟级，调试链路长 |
| 桌面 UI | MyGo（immediate mode）单体二进制 | Flutter 需附带 ~15MB 运行时 + 内核 exe |
| 协议覆盖 | 已覆盖 Reality / QUIC / Hysteria2 / TUIC | 覆盖度相近，但深度落后 |
| 分发体积 | 单个 exe | Flutter 客户端 + 内核 exe 两个文件 |

结论：**个人维护的桌面代理客户端，Go 版是更合适的主线**。
Rust 版只在「需要 TUN / 极低延迟包处理 / 底层加密加速」这些确有收益的场景才值得单独投入。

Rust 版沉淀下来的**安全设计与错误处理经验**已被全部移植到 Go 版，见下文。

---

## 二、已移植到 Go 版的能力

### 2.1 订阅安全：严格校验 + 失败保留旧配置

Rust 版结论（已落地）：

- 订阅响应必须是**真正的非空 Clash YAML mapping**，且顶层至少包含一个已知键
  （`proxies` / `proxy-groups` / `rules` / `mixed-port` / `port` / `socks-port` /
  `dns` / `mode` / `allow-lan` / `log-level` / `external-controller` 等）。
- HTML 挑战页、JSON 错误页、空响应一律拒绝。
- 下载 → 校验 → 临时文件写入 → `os.Rename` 原子替换。任一步失败，旧配置原样保留。

Go 版对应实现：

| 位置 | 函数 | 说明 |
|---|---|---|
| `internal/profile/profile.go` | `ValidateConfig` | 顶层键白名单校验 |
| `internal/profile/profile.go` | `downloadSubscription` | 唯一取数路径，导入与刷新共用 |
| `internal/profile/profile.go` | `Refresh` | 先校验再落盘，失败保留旧配置 |
| `internal/profile/profile.go` | `decodeSubscription` / `decodeSubscriptionFromFile` | base64 订阅解码 |

### 2.2 分享链接订阅自动转换

Rust 版与 Go 版实现一致（`internal/profile/sharelinks.go`）：

支持 `vmess://` `vless://` `trojan://` `ss://` `hysteria2://` `hy2://` `tuic://`。

关键点：

1. **只在 YAML 校验失败后回退转换**，不改变正常 Clash 订阅的处理路径。
2. 转换结果生成最小可用配置：`proxies` + `proxy-groups`（`PROXY` select + `自动选择` url-test）+ `rules`。
3. VLESS Reality 参数写入 `reality-opts.public-key` / `reality-opts.short-id`。
4. **不写 `flow: xtls-rprx-vision`**——自研内核没有实现 Vision 流控，
   写上去反而会让真实节点握手失败。

### 2.3 国内直连兜底（节点失效不整机断网）

**这是 Rust 版最有价值的发现，已移植。**

问题：很多机场订阅只给一条 `MATCH,PROXY`。一旦节点全部失效，
国内网站也会跟着一起断网，用户以为"软件坏了"。

方案：在**生成运行时配置**这一步（而不是存储订阅文件时），
检查配置里是否已存在指向 `DIRECT` 的规则；**完全没有**时，在 `rules:` 列表最前面插入：

```yaml
rules:
  - GEOSITE,geolocation-cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY        # 用户原有规则
```

安全约定：

- 已有任何 DIRECT 规则 → **原样返回**，绝不改动用户自己的分流逻辑。
- `rules: [A,B]` 内联数组写法无法安全插入 → 原样返回。
- 配置文件里根本没有 `rules:` 段 → 原样返回。
- 兜底只作用于**实际生效的运行时配置**，磁盘上存储的订阅文件保持原样，
  这样「重新下载订阅」时能拿到服务端最新内容，不会被本地改写污染。

Go 版落地位置：

| 位置 | 说明 |
|---|---|
| `internal/profile/directfallback.go` | `EnsureDirectFallback` 实现 |
| `internal/profile/directfallback_test.go` | 4 个用例：补规则 / 不动已有规则 / 内联数组跳过 / 无 rules 跳过 |
| `internal/runtime/runtime.go` | 在 enhance 管线之前调用 |

### 2.4 系统代理退出保护（只清自己开的代理）

Rust 版用了 `PortGuard`（RAII）：进程退出时检查系统代理是否仍指向本内核端口，
是才关闭。Go 版对应实现：

| 位置 | 函数 | 说明 |
|---|---|---|
| `internal/sysproxy/sysproxy.go` | `PointsTo(port)` | 判断系统代理是否指向本机该端口 |
| `internal/sysproxy/sysproxy.go` | `serverMatchesPort` | 兼容 `127.0.0.1:7897` 与 `http=…;https=…` 两种写法，兼容 IPv6 `[::1]:7897` |
| `internal/sysproxy/sysproxy.go` | `ClearIfPointsTo(port)` | 只在指向自己时才关闭 |
| `main.go` | `OnBeforeQuit` | 退出清理改用 `ClearIfPointsTo` |

**为什么重要**：如果用户在 ClashGo 运行期间手动把系统代理指向了别的工具
（比如公司 VPN），退出时无条件 `Set(false)` 会把用户的 VPN 配置一起抹掉。

### 2.5 节点健康告警（只告警，不自动改设置）

Rust 版 Flutter 端实现了「所有节点都不可用」的告警条，
并明确约定：**程序绝不自动关闭系统代理**。

Go 版已移植：

| 位置 | 说明 |
|---|---|
| `ui/proxy_helpers.go` | `checkNodesHealth()` 对所有代理组做一次测速体检 |
| `ui/proxy_helpers.go` | `updateHealthFromDelays()` 复用已有测速结果，不额外发请求 |
| `ui/banner_nodes.go` | 首页告警条：提示 + 「重新检测」+「关闭系统代理」按钮 |
| `ui/app.go` | `applySystemProxy` 中开启系统代理后自动体检一次 |

约定：

- 告警条只**提示**，关闭系统代理必须由用户点按钮。
- 测速结果为空时**不**判定为全挂（避免"没测过"被误报成"全挂了"）。
- 关闭系统代理这个动作走的是 `applySystemProxy()`，和其他开关行为一致。

### 2.6 构建期处理被占用的可执行文件

Rust 版用 Cargo + Flutter 双构建链，Windows 上安装阶段会因
`clashgo-kernel.exe` 被正在运行的进程占用而失败。

**通用解法**（Go 版构建脚本同样适用）：构建前主动结束旧进程。

Go 版的 `build-setup.sh` 已包含类似处理。

### 2.7 API 请求体读取的坑

Rust 版用裸 `TcpStream` 实现 HTTP 服务时踩过：
`stream.read_to_string()` 会一直等到客户端关闭连接才返回，
导致 `POST /sysproxy/enable` 看起来"无响应"（实际是服务端在等 EOF）。

**正确做法**：按 `Content-Length` 精确读取。

Go 版用 `net/http`，没有这个问题；此条记录下来供将来写原生协议时参考。

### 2.8 cfgscript 下标基线

Rust 版对齐 Go 版，把 Lua 风格的下标基线统一为 **1-based**
（`config.proxies[1]` 是第一个元素），两版行为一致。

---

## 三、Rust 版暴露出的通用工程经验

### 3.1 源码按职责分目录，但保持模块路径

Rust 版把平铺的 `kernel/src/*.rs` 拆成
`api/ config/ proxy/ outbound/ inbound/ network/ logging/ security/ core/ crypto/`，
同时用 `#[path = "..."]` 保留原有的 `crate::<模块名>` 调用路径。

**教训**：大文件拆分时，路径组织和符号路径可以解耦。
Go 版虽然用包路径天然隔离，但同样应注意避免出现"一个包塞进几十个文件"的情况。

### 3.2 配置解析的边界情况

Rust 版在解析 Clash YAML 时发现一个 bug：空内联列表 `[]`
会被解析成一个"空节点"而不是空数组，导致 `proxies: []` 的配置被误判。

**教训**：YAML 的空值语义（`null` / `[]` / `{}`）必须分别处理，
Go 版 `internal/yaml/decode.go` 已覆盖这些情况。

### 3.3 密码学原语的自研边界

Reality 需要 X25519 + HKDF + AES-GCM + Ed25519。
Rust 版直接用成熟 crate；Go 版用标准库手写（`crypto/ecdh` + `crypto/hmac` +
`crypto/aes` + `crypto/cipher`），已通过与官方实现的对照测试。

**教训**：自研密码学只适合"算法固定、测试向量可对照"的场景。
TLS 记录层和握手状态机这类复杂协议，不建议手写。

### 3.4 节点失效时要区分"代码问题"和"节点问题"

Reality 握手打通后仍然 `read VLESS response: EOF`。
用 mihomo 官方实现对照同样 EOF，才确认是**节点本身失效**，不是自研内核的 bug。

**教训**：自研协议栈一定要准备一个"官方实现的对照测试"。
否则分不清是代码写错了还是对端不配合。

---

## 四、ClashRS 保留的独立价值

ClashRS 仓库（`clashrs`）作为 Rust 实现的完整参考保留，其价值在于：

- 一个**完全独立的第二实现**，可以用来交叉验证协议行为。
- 展示 Flutter + 本地内核进程管理的客户端组织方式（Rust 版曾采用）。
- 记录了 QUIC / HTTP/3 / gRPC / WireGuard 深度特性的推进路径。

Go 版未来要补齐的深层协议能力（与 Rust 版当时的差距清单一致）：

- QUIC：0-RTT / 连接迁移 / key update
- HTTP/3：完整连接级阻塞流状态机
- gRPC：完整 HPACK / TLS
- WireGuard：拥塞控制 / SACK / 窗口缩放

---

## 五、桌面系统集成对照

ClashRS 采用 Flutter，桌面系统集成靠插件生态；
ClashGo 采用 MyGo，集成全部自己实现，因此功能更全但维护量更大。

ClashGo 已实现（ClashRS 未实现或简化）：

- 系统代理开关 / PAC 模式 / 虚拟网卡（TUN）
- 开机自启（`internal/autostart`）
- 免安装绿色版与安装包双形态（`internal/installer`）
- 隐藏到托盘 + 单实例唤醒
- 端口冲突自动回退（`internal/portfallback`）
- 崩溃残留清理（`internal/bootguard`）
- 通知中心 / 媒体解锁检测 / 备份与 WebDAV / 自动分组 / 节点探测
