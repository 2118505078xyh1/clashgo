package minikernel

import (
	"context"
	"fmt"
	"net"

	"clashgo/internal/wgproto"
)

// wgOut 是 WireGuard 出站。WireGuard 是三层隧道，
// 这里用 ipstack 的简化思路：在 WG 的 PacketConn 上跑一个用户态连接。
type wgOut struct {
	name   string
	cfg    wgproto.Config
	tunnel *wgproto.Tunnel
}

func newWireGuard(name string, cfg wgproto.Config) *wgOut {
	return &wgOut{name: name, cfg: cfg}
}

func (w *wgOut) Name() string { return w.name }

// start 启动 WG 隧道（懒启动，第一次拨号时）。
func (w *wgOut) start() error {
	if w.tunnel != nil {
		return nil
	}
	t, err := wgproto.New(w.cfg)
	if err != nil {
		return err
	}
	if err := t.Start(); err != nil {
		return err
	}
	w.tunnel = t
	return nil
}

func (w *wgOut) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	if err := w.start(); err != nil {
		return nil, fmt.Errorf("wireguard start: %w", err)
	}
	// WireGuard 是三层隧道，需要用户态 TCP/IP 栈把 net.Conn 映射为 IP 流。
	// 完整实现见 wgStackConn；当前返回隧道 PacketConn 的流式包装。
	host := m.Host
	if host == "" && m.DstIP.IsValid() {
		host = m.DstIP.String()
	}
	return newWGStackConn(w.tunnel, host, m.DstPort), nil
}
