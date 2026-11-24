package minikernel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"clashgo/internal/dnsproto"
	"clashgo/internal/quicproto"
	"clashgo/internal/ruleindex"
)

// DNSConfig 是内核 DNS 配置。
type DNSConfig struct {
	Enable       bool              `yaml:"enable"`
	Listen       string            `yaml:"listen"`
	EnhancedMode string            `yaml:"enhanced-mode"` // fake-ip / redir-host / normal
	FakeIPRange  string            `yaml:"fake-ip-range"`
	Nameserver   []string          `yaml:"nameserver"`
	Fallback     []string          `yaml:"fallback"`
	Hosts        map[string]string `yaml:"hosts"`
}

// FakeIPPool 维护 hostname ↔ 假 IP 的双向映射。
type FakeIPPool struct {
	mu     sync.RWMutex
	next   uint32
	base   netip.Addr
	byHost map[string]netip.Addr
	byIP   map[netip.Addr]string
}

func newFakeIPPool(cidr string) *FakeIPPool {
	base := netip.MustParseAddr("198.18.0.1")
	if cidr != "" {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			base = p.Addr()
		}
	}
	return &FakeIPPool{base: base, byHost: map[string]netip.Addr{}, byIP: map[netip.Addr]string{}}
}

func (p *FakeIPPool) Lookup(host string) netip.Addr {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.byHost[host]; ok {
		return ip
	}
	p.next++
	ip := netip.AddrFrom4([4]byte{
		p.base.As4()[0], p.base.As4()[1],
		byte(p.next >> 8), byte(p.next),
	})
	p.byHost[host] = ip
	p.byIP[ip] = host
	return ip
}

func (p *FakeIPPool) LookBack(ip netip.Addr) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	h, ok := p.byIP[ip]
	return h, ok
}

// DNSServer 是内置 DNS 服务（hosts → fake-ip → 上游）。
type DNSServer struct {
	cfg  DNSConfig
	pool *FakeIPPool
	k    *Kernel
	srv  *dnsproto.Server
}

func startDNS(k *Kernel, cfg DNSConfig) (*DNSServer, error) {
	listen := cfg.Listen
	if listen == "" {
		listen = "0.0.0.0:1053"
	}
	s := &DNSServer{cfg: cfg, pool: newFakeIPPool(cfg.FakeIPRange), k: k}
	s.srv = &dnsproto.Server{Addr: listen, Net: "udp", Handler: dnsproto.HandlerFunc(s.serveDNS)}
	go func() { _ = s.srv.ListenAndServe() }()
	return s, nil
}

func (s *DNSServer) Close() error {
	if s.srv != nil {
		return s.srv.Shutdown()
	}
	return nil
}

func (s *DNSServer) serveDNS(w dnsproto.ResponseWriter, req *dnsproto.Msg) {
	msg := new(dnsproto.Msg)
	msg.SetReply(req)
	for _, q := range req.Question {
		name := strings.TrimSuffix(q.Name, ".")
		if ip := s.hostsLookup(name); ip.IsValid() {
			msg.AddA(q.Name, 300, ip.AsSlice())
			continue
		}
		if strings.EqualFold(s.cfg.EnhancedMode, "fake-ip") && (q.Qtype == dnsproto.TypeA || q.Qtype == dnsproto.TypeAAAA) {
			ip := s.pool.Lookup(name)
			if ip.Is4() {
				msg.AddA(q.Name, 1, ip.AsSlice())
			}
			continue
		}
		// 上游解析。
		ips := s.upstreamResolve(context.Background(), name, q.Qtype)
		for _, ip := range ips {
			if ip.Is4() {
				msg.AddA(q.Name, 300, ip.AsSlice())
			}
		}
	}
	_ = w.WriteMsg(msg)
}

func (s *DNSServer) hostsLookup(name string) netip.Addr {
	if v, ok := s.cfg.Hosts[name]; ok {
		if ip, err := netip.ParseAddr(v); err == nil {
			return ip
		}
	}
	return netip.Addr{}
}

func (s *DNSServer) upstreamResolve(ctx context.Context, name string, qtype uint16) []netip.Addr {
	servers := s.cfg.Nameserver
	if len(servers) == 0 {
		servers = []string{"223.5.5.5:53", "119.29.29.29:53"}
	}
	qt := qtype
	if qt != dnsproto.TypeA && qt != dnsproto.TypeAAAA {
		qt = dnsproto.TypeA
	}
	m := new(dnsproto.Msg)
	m.SetQuestion(dnsproto.Fqdn(name), qt)
	client := &dnsproto.Client{Timeout: 3 * time.Second}
	for _, server := range servers {
		// DoQ：用自研真 QUIC 栈查询（doq://host:port）。
		if strings.HasPrefix(server, "doq://") {
			addr := strings.TrimPrefix(server, "doq://")
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				host = addr
			}
			r, err := exchangeDoQ(ctx, addr, host, m)
			if err != nil {
				continue
			}
			var out []netip.Addr
			for _, ip := range r.AnswerIPs() {
				if a, ok := netip.AddrFromSlice(ip); ok {
					out = append(out, a)
				}
			}
			if len(out) > 0 {
				return out
			}
			continue
		}
		if !strings.Contains(server, ":") && !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "tls://") {
			server += ":53"
		}
		r, _, err := client.ExchangeSecure(ctx, m, server)
		if err != nil {
			continue
		}
		var out []netip.Addr
		for _, ip := range r.AnswerIPs() {
			if a, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, a)
			}
		}
		if len(out) > 0 {
			// fallback 防污染：若配置了 fallback，且主 DNS 解析结果全为境外 IP，
			// 则用 fallback DNS 的结果替换（通常是国内 DNS，拿到真实 IP）。
			if len(s.cfg.Fallback) > 0 && !anyIPInChina(out) {
				if fb := s.resolveVia(ctx, client, m, s.cfg.Fallback); len(fb) > 0 {
					return fb
				}
			}
			return out
		}
	}
	return nil
}

// resolveVia 用指定的 DNS 服务器列表解析。
func (s *DNSServer) resolveVia(ctx context.Context, client *dnsproto.Client, m *dnsproto.Msg, servers []string) []netip.Addr {
	for _, server := range servers {
		if strings.HasPrefix(server, "doq://") {
			addr := strings.TrimPrefix(server, "doq://")
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				host = addr
			}
			if r, err := exchangeDoQ(ctx, addr, host, m); err == nil {
				if ips := r.AnswerIPs(); len(ips) > 0 {
					var out []netip.Addr
					for _, ip := range ips {
						if a, ok := netip.AddrFromSlice(ip); ok {
							out = append(out, a)
						}
					}
					if len(out) > 0 {
						return out
					}
				}
			}
			continue
		}
		if !strings.Contains(server, ":") && !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "tls://") {
			server += ":53"
		}
		r, _, err := client.ExchangeSecure(ctx, m, server)
		if err != nil {
			continue
		}
		var out []netip.Addr
		for _, ip := range r.AnswerIPs() {
			if a, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, a)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// anyIPInChina 判断 IP 列表中是否有中国 IP（用完整 GeoIP 数据库）。
func anyIPInChina(ips []netip.Addr) bool {
	for _, p := range ruleindex.GeoIPCidrs("cn") {
		for _, ip := range ips {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// exchangeDoQ 用自研真 QUIC 栈发起 DoQ 查询（RFC 9250）。
func exchangeDoQ(ctx context.Context, addr, serverName string, req *dnsproto.Msg) (*dnsproto.Msg, error) {
	conn, err := quicproto.DialDoQ(ctx, addr, serverName, true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	wire, err := dnsproto.Pack(req)
	if err != nil {
		return nil, err
	}
	respWire, err := conn.ExchangeDNS(ctx, wire)
	if err != nil {
		return nil, err
	}
	return dnsproto.Unpack(respWire)
}

// ResolveHost 用上游 DNS 解析域名（供 DIRECT 出站使用，避免走自身 DNS 造成环路）。
func (s *DNSServer) ResolveHost(host string) (netip.Addr, error) {
	ips := s.upstreamResolve(context.Background(), host, dnsproto.TypeA)
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: no answer", host)
	}
	return ips[0], nil
}
