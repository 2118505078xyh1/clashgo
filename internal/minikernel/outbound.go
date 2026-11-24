package minikernel

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"
)

// Direct 出站：直接拨号到目标。
type Direct struct{}

func (d *Direct) Name() string { return "DIRECT" }
func (d *Direct) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	addr := m.RemoteAddress()
	if m.ResolvedIP.IsValid() {
		addr = net.JoinHostPort(m.ResolvedIP.String(), strconv.Itoa(int(m.DstPort)))
	}
	if addr == "" {
		return nil, &DialError{"DIRECT: empty destination"}
	}
	netd := net.Dialer{Timeout: 10 * time.Second}
	return netd.DialContext(ctx, "tcp", addr)
}

// Reject 出站：返回"读即 EOF"的假连接（不返回 error，让流程正常走完）。
type Reject struct{}

func (r *Reject) Name() string { return "REJECT" }
func (r *Reject) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	return &rejectConn{}, nil
}

type rejectConn struct{}

func (*rejectConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*rejectConn) Write(b []byte) (int, error)      { return 0, io.EOF }
func (*rejectConn) Close() error                     { return nil }
func (*rejectConn) LocalAddr() net.Addr              { return rejectAddr{} }
func (*rejectConn) RemoteAddr() net.Addr             { return rejectAddr{} }
func (*rejectConn) SetDeadline(time.Time) error      { return nil }
func (*rejectConn) SetReadDeadline(time.Time) error  { return nil }
func (*rejectConn) SetWriteDeadline(time.Time) error { return nil }

type rejectAddr struct{}

func (rejectAddr) Network() string { return "reject" }
func (rejectAddr) String() string  { return "reject" }

// DialError 是出站拨号错误。
type DialError struct{ Msg string }

func (e *DialError) Error() string { return e.Msg }
