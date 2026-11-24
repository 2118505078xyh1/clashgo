package minikernel

import (
	"context"
	"fmt"
	"net"
	"time"

	"clashgo/internal/ssproto"
)

// ShadowSocks 是 Shadowsocks 出站（纯标准库自研 AEAD 实现）。
type ShadowSocks struct {
	name   string
	server string // host:port
	method *ssproto.Method
}

// NewShadowSocks 创建一个 SS 出站。cipherMethod 如 "aes-256-gcm"。
func NewShadowSocks(name, server, cipherMethod, password string) (*ShadowSocks, error) {
	method, err := ssproto.NewMethod(cipherMethod, password)
	if err != nil {
		return nil, fmt.Errorf("create ss method: %w", err)
	}
	return &ShadowSocks{name: name, server: server, method: method}, nil
}

func (s *ShadowSocks) Name() string { return s.name }

// ListenPacket 建立 SS UDP 通道（目标地址写在加密头中）。
func (s *ShadowSocks) ListenPacket(ctx context.Context, m *Metadata) (net.PacketConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", s.server)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	pc, err := s.method.ListenPacket(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return pc, nil
}

func (s *ShadowSocks) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	if host == "" {
		return nil, &DialError{"SS: empty destination"}
	}
	netd := net.Dialer{Timeout: 10 * time.Second}
	raw, err := netd.DialContext(ctx, "tcp", s.server)
	if err != nil {
		return nil, err
	}
	conn, err := s.method.Dial(raw, host, m.DstPort)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}
