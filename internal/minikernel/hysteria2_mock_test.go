package minikernel

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"clashgo/internal/quicproto"
)

// mockHyConn / mockHyStream 用 net.Pipe 模拟 QUIC 连接与流，
// 用于在无真实 QUIC 服务端的情况下验证 Hysteria2 TCP 数据面帧格式。
type mockHyConn struct {
	streams chan quicproto.Stream
}

func (c *mockHyConn) OpenStream() (quicproto.Stream, error) {
	s := <-c.streams
	return s, nil
}
func (c *mockHyConn) OpenUniStream() (quicproto.Stream, error) {
	return c.OpenStream()
}
func (c *mockHyConn) SendDatagram([]byte) error                       { return nil }
func (c *mockHyConn) ReceiveDatagram(context.Context) ([]byte, error) { return nil, io.EOF }
func (c *mockHyConn) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	return make([]byte, 32), nil
}
func (c *mockHyConn) InitiateKeyUpdate() error { return nil }
func (c *mockHyConn) Close() error             { return nil }

type mockHyStream struct {
	net.Conn
	id uint64
}

func (s *mockHyStream) StreamID() uint64  { return s.id }
func (s *mockHyStream) CloseWrite() error { return nil }

// TestHysteria2TCPDataPlane 验证 TCPRequest/TCPResponse 帧交互及后续字节流透传。
func TestHysteria2TCPDataPlane(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	conn := &mockHyConn{streams: make(chan quicproto.Stream, 1)}
	conn.streams <- &mockHyStream{Conn: clientEnd, id: 0}

	h := &hysteria2Real{
		name:       "hy2-test",
		serverAddr: "127.0.0.1:443",
		conn:       conn, // 跳过 ensure 的真实 QUIC 握手
	}

	// 服务端 goroutine：读 TCPRequest → 回 TCPResponse → echo 数据。
	serverErr := make(chan error, 1)
	go func() {
		defer close(serverErr)
		r := bufio.NewReader(serverEnd)
		ft, err := hyReadVarint(r)
		if err != nil {
			serverErr <- err
			return
		}
		if ft != hyFrameTypeTCPRequest {
			serverErr <- &mockErr{"wrong frame type"}
			return
		}
		addrLen, err := hyReadVarint(r)
		if err != nil {
			serverErr <- err
			return
		}
		addr := make([]byte, addrLen)
		if _, err := io.ReadFull(r, addr); err != nil {
			serverErr <- err
			return
		}
		padLen, err := hyReadVarint(r)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			serverErr <- err
			return
		}
		if string(addr) != "example.com:443" {
			serverErr <- &mockErr{"wrong address: " + string(addr)}
			return
		}
		// TCPResponse: status=0, msgLen=0, padLen=0
		resp := []byte{0, 0, 0}
		if _, err := serverEnd.Write(resp); err != nil {
			serverErr <- err
			return
		}
		// echo 收到的数据
		buf := make([]byte, 64)
		n, err := serverEnd.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := serverEnd.Write(bytes.ToUpper(buf[:n])); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	m := &Metadata{Network: "tcp", Host: "example.com", DstPort: 443}
	remote, err := h.DialContext(context.Background(), m)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer remote.Close()

	if _, err := remote.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(remote, got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "HELLO" {
		t.Fatalf("echo = %q, want HELLO", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

type mockErr struct{ msg string }

func (e *mockErr) Error() string { return e.msg }

// TestHysteria2RejectedTarget 验证服务端拒绝目标时 DialContext 返回错误。
func TestHysteria2RejectedTarget(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	conn := &mockHyConn{streams: make(chan quicproto.Stream, 1)}
	conn.streams <- &mockHyStream{Conn: clientEnd, id: 0}
	h := &hysteria2Real{name: "hy2-test", serverAddr: "127.0.0.1:443", conn: conn}

	go func() {
		r := bufio.NewReader(serverEnd)
		_, _ = hyReadVarint(r) // frame type
		l, _ := hyReadVarint(r)
		_, _ = io.CopyN(io.Discard, r, int64(l))
		p, _ := hyReadVarint(r)
		_, _ = io.CopyN(io.Discard, r, int64(p))
		// status=1, msgLen=6, "denied", padLen=0
		resp := append([]byte{1, 6}, []byte("denied")...)
		resp = append(resp, 0)
		_, _ = serverEnd.Write(resp)
	}()

	m := &Metadata{Network: "tcp", Host: "blocked.com", DstPort: 80}
	if _, err := h.DialContext(context.Background(), m); err == nil {
		t.Fatal("expected error for rejected target")
	}
}
