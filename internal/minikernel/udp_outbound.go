package minikernel

import (
	"context"
	"io"
	"net"
	"time"
)

// Direct UDP：创建一个本地 UDP socket，目标地址由 WriteTo 指定。
func (d *Direct) ListenPacket(ctx context.Context, m *Metadata) (net.PacketConn, error) {
	return net.ListenPacket("udp", "0.0.0.0:0")
}

// Reject UDP：静默丢弃所有包。
func (r *Reject) ListenPacket(ctx context.Context, m *Metadata) (net.PacketConn, error) {
	return &rejectPacketConn{}, nil
}

type rejectPacketConn struct{}

func (*rejectPacketConn) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (*rejectPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (*rejectPacketConn) Close() error                              { return nil }
func (*rejectPacketConn) LocalAddr() net.Addr                       { return rejectAddr{} }
func (*rejectPacketConn) SetDeadline(time.Time) error               { return nil }
func (*rejectPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*rejectPacketConn) SetWriteDeadline(time.Time) error          { return nil }
