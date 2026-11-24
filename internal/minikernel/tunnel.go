package minikernel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// preHandleMetadata 在选路前把 fake-ip 反查回域名，让 DOMAIN 规则能命中。
func (k *Kernel) preHandleMetadata(m *Metadata) {
	if k.DNS == nil {
		k.setupLazyResolve(m)
		return
	}
	if m.DstIP.IsValid() {
		if host, ok := k.DNS.pool.LookBack(m.DstIP); ok {
			m.Host = host
			m.DstIP = netip.Addr{}
			// 真实 IP 供 DIRECT 出站使用，避免再次查询本机 DNS 形成环路。
			if ip, err := k.DNS.ResolveHost(host); err == nil {
				m.ResolvedIP = ip
			}
		}
	}
	k.setupLazyResolve(m)
}

// setupLazyResolve 为"只有域名没有 IP"的连接设置惰性解析闭包，
// 只有 IP-CIDR / GEOIP 规则真正需要时才触发 DNS 查询，且只查一次。
func (k *Kernel) setupLazyResolve(m *Metadata) {
	if m.Host == "" || m.DstIP.IsValid() {
		return
	}
	var once sync.Once
	var ip netip.Addr
	m.ResolveIP = func() netip.Addr {
		once.Do(func() {
			if k.DNS != nil {
				ip, _ = k.DNS.ResolveHost(m.Host)
			} else if resolved, err := netip.ParseAddr(m.Host); err == nil {
				ip = resolved
			}
		})
		return ip
	}
}

// selectProxy 按模式/规则选出站（不含拨号），TCP 与 UDP 共用。
func (k *Kernel) selectProxy(m *Metadata) ProxyAdapter {
	k.preHandleMetadata(m)
	snap := k.snapshot() // 读取不可变快照，热重载时现有连接不受影响
	name := m.SpecialProxy
	if name == "" {
		switch snap.Mode {
		case "direct":
			name = "DIRECT"
		case "global":
			if _, ok := snap.Proxies["GLOBAL"]; ok {
				name = "GLOBAL"
			} else {
				name = "DIRECT"
			}
		default:
			name = "DIRECT"
			// 纯域名规则且数量较多时用 Trie 加速（O(域名层级)），
			// 仍按配置顺序（priority=索引）取最早命中，语义等价。
			if snap.pureDomain && snap.domainTrie != nil && m.RuleHost() != "" {
				if adapter, idx, ok := snap.domainTrie.Match(m.RuleHost()); ok {
					name = adapter
					r := snap.Rules[idx]
					m.MatchedRule = r.Type()
					m.MatchedPayload = r.Payload()
				}
			} else {
				for _, r := range snap.Rules {
					if ok, target := r.Match(m); ok {
						name = target
						m.MatchedRule = r.Type()
						m.MatchedPayload = r.Payload()
						break
					}
				}
			}
		}
	}
	m.MatchedProxy = name
	p, ok := snap.Proxies[name]
	if !ok {
		p = snap.Proxies["DIRECT"]
		m.MatchedProxy = "DIRECT"
	}
	return p
}

// route 按规则选出站并拨号，返回远端连接。
func (k *Kernel) route(ctx context.Context, m *Metadata) (net.Conn, error) {
	return k.selectProxy(m).DialContext(ctx, m)
}

// UDPProxyAdapter 是支持 UDP 的出站（可选接口）。
type UDPProxyAdapter interface {
	ListenPacket(ctx context.Context, m *Metadata) (net.PacketConn, error)
}

// Dispatch 处理一条入站连接：选路 + 拨号 + 双向转发。
func (k *Kernel) Dispatch(ctx context.Context, client net.Conn, m *Metadata) error {
	remote, err := k.route(ctx, m)
	if err != nil {
		k.log("error", "连接失败 "+m.String()+" : "+err.Error())
		return err
	}
	defer client.Close()

	// 记录连接建立：主机 + 规则 + 选中代理。
	via := m.MatchedProxy
	if via == "" {
		via = "DIRECT"
	}
	k.log("info", "使用代理 "+via+"["+m.MatchedRule+"] 连接 "+m.String())

	chain := []string{m.MatchedProxy}
	src := ""
	if tcp, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		src = tcp.IP.String()
	}
	dst := m.Host
	if dst == "" && m.DstIP.IsValid() {
		dst = m.DstIP.String()
	}
	info := &ConnInfo{
		Start:         time.Now(),
		Host:          m.Host,
		Full:          m.String(),
		Network:       m.Network,
		Type:          m.Type,
		Rule:          m.MatchedRule,
		RulePayload:   m.MatchedPayload,
		Chain:         chain,
		SourceIP:      src,
		DestinationIP: dst,
		conn:          client,
	}
	k.Connections.join(info)
	tracked := &trackedConn{Conn: remote, info: info, k: k}

	k.activeConns.Add(1)
	defer k.activeConns.Add(-1)
	defer info.CloseConn()
	defer tracked.Close()
	relay(client, tracked)
	return nil
}

// relay 双向转发数据，任一端关闭时通知另一端半关闭，避免对端阻塞。
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}
	go copyHalf(b, a)
	go copyHalf(a, b)
	wg.Wait()
}
