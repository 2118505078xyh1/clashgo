package minikernel

import (
	"context"
	"fmt"
	"net"
	"time"

	"clashgo/internal/ssrproto"
)

// ssrOut 是 ShadowsocksR 出站。
type ssrOut struct {
	name   string
	server string
	cfg    ssrproto.Config
}

func newSSR(name, server string, cfg ssrproto.Config) *ssrOut {
	return &ssrOut{name: name, server: server, cfg: cfg}
}

func (s *ssrOut) Name() string { return s.name }

func (s *ssrOut) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"SSR: empty destination"}
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", s.server)
	if err != nil {
		return nil, err
	}
	conn, err := ssrproto.Dial(raw, s.cfg, host, m.DstPort)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("SSR handshake: %w", err)
	}
	return conn, nil
}
