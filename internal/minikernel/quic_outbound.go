package minikernel

import (
	"context"
	"net"

	"clashgo/internal/quicproto"
)

// hysteriaOut 把 quicproto 的 Hysteria2/TUIC 连接适配成 ProxyAdapter。
type quicOut struct {
	name string
	kind string // "hysteria2" / "tuic"
	cfg  quicproto.Config
}

func newHysteria2(name, server, password, serverName string, skipVerify bool, bandwidth int) *quicOut {
	return &quicOut{
		name: name, kind: "hysteria2",
		cfg: quicproto.Config{
			Server: server, Password: password, ServerName: serverName,
			SkipVerify: skipVerify, Bandwidth: bandwidth,
		},
	}
}

func newTUIC(name, server, uuid, token, serverName string, skipVerify bool) *quicOut {
	return &quicOut{
		name: name, kind: "tuic",
		cfg: quicproto.Config{
			Server: server, UUID: uuid, Token: token, ServerName: serverName,
			SkipVerify: skipVerify,
		},
	}
}

func (q *quicOut) Name() string { return q.name }

func (q *quicOut) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"quic: empty destination"}
	}
	if q.kind == "tuic" {
		return quicproto.DialTUIC(ctx, q.cfg, host, m.DstPort)
	}
	return quicproto.DialHysteria2(ctx, q.cfg, host, m.DstPort)
}
