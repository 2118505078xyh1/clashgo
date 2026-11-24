// Package minikernel 是 clashgo 自研的纯 Go 代理内核。
//
// 设计原则（来自对现有内核的深入研究）：
//   - Metadata 是唯一枢纽：入站产生它、规则读取它、出站消费它
//   - 出站接口极薄：只有 DialContext(ctx, *Metadata)
//   - 规则保留配置顺序语义（first-match-wins）
//   - 统计用装饰器包装连接
//
// 本包实现阶段 0+1：mixed 入站(SOCKS5/HTTP) + 规则 + DIRECT/REJECT + 双向转发。
package minikernel

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Metadata 是一条连接的"身份描述"，贯穿全内核。
type Metadata struct {
	Network      string // "tcp" / "udp"
	Type         string // "socks5" / "http" / "https"
	SrcIP        netip.Addr
	DstIP        netip.Addr
	SrcPort      uint16
	DstPort      uint16
	Host         string            // 目标域名（无域名时为空，靠 DstIP）
	InName       string            // 入站类型：socks5 / http / tun（IN-TYPE 规则用）
	Process      string            // 进程名（PROCESS-NAME 规则用）
	SpecialProxy string            // 强制代理名（覆盖规则）
	ResolvedIP   netip.Addr        // fake-ip 反查得到的真实 IP（DIRECT 出站用）
	ResolveIP    func() netip.Addr // 惰性解析（带 once 缓存），仅 IP 规则需要时调用

	// 由 route 填充，供连接快照展示。
	MatchedRule    string
	MatchedPayload string
	MatchedProxy   string
}

// RuleHost 返回用于规则匹配的域名（sniffer 可覆盖 Host，此处简化）。
func (m *Metadata) RuleHost() string { return strings.ToLower(m.Host) }

// RemoteAddress 返回出站拨号地址（域名优先，其次 IP）。
func (m *Metadata) RemoteAddress() string {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(m.DstPort)))
}

func (m *Metadata) String() string { return m.Network + " " + m.RemoteAddress() }

// ProxyAdapter 是出站代理的最小接口——极薄，只有拨号。
type ProxyAdapter interface {
	Name() string
	DialContext(ctx context.Context, m *Metadata) (net.Conn, error)
}

// Rule 是规则接口：输入 metadata，输出 (是否命中, 目标代理名)。
type Rule interface {
	Type() string
	Payload() string
	Adapter() string
	Match(m *Metadata) (bool, string)
}

// Stats 是内核的运行时统计。
type Stats struct {
	UploadTotal   int64
	DownloadTotal int64
	ActiveConns   int64
}

// Kernel 是自研内核主体。
type Kernel struct {
	Mode        string // "rule" / "global" / "direct"（保留供 API 读取最新值）
	Rules       []Rule
	Proxies     map[string]ProxyAdapter
	Connections *ConnManager
	DNS         *DNSServer
	TUN         *TUNServer

	// 热重载：运行配置存在原子快照里，现有连接用旧快照，新连接用新快照。
	cfgSnap atomic.Pointer[configSnapshot]

	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	activeConns   atomic.Int64
	paused        atomic.Bool

	// logMu 保护日志回调（由 APIServer 注册，内核在关键路径调用）。
	logMu   sync.RWMutex
	logSink func(typ, payload string)
}

// SetLogSink 注册日志回调（APIServer 用于把内核事件广播到 /logs）。
func (k *Kernel) SetLogSink(fn func(typ, payload string)) {
	k.logMu.Lock()
	k.logSink = fn
	k.logMu.Unlock()
}

// log 发送一条内核日志（无订阅者时为空操作）。
func (k *Kernel) log(typ, payload string) {
	k.logMu.RLock()
	fn := k.logSink
	k.logMu.RUnlock()
	if fn != nil {
		fn(typ, payload)
	}
}

// SetPaused 暂停/恢复接收新连接（供轻量模式的空闲挂起使用）。
func (k *Kernel) SetPaused(p bool) { k.paused.Store(p) }

// IsPaused 报告当前是否暂停接收新连接。
func (k *Kernel) IsPaused() bool { return k.paused.Load() }

// NewKernel 创建一个带 DIRECT/REJECT 内置出站的内核。
func NewKernel() *Kernel {
	k := &Kernel{
		Mode: "rule",
		Proxies: map[string]ProxyAdapter{
			"DIRECT": &Direct{},
			"REJECT": &Reject{},
		},
		Connections: NewConnManager(),
	}
	k.initSnapshot()
	return k
}

// Stats 返回当前统计快照。
func (k *Kernel) Stats() Stats {
	return Stats{
		UploadTotal:   k.uploadTotal.Load(),
		DownloadTotal: k.downloadTotal.Load(),
		ActiveConns:   k.activeConns.Load(),
	}
}
