package minikernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"clashgo/internal/quicproto"
)

func TestTUICSerializeAddrRoundTrip(t *testing.T) {
	for _, addr := range []string{"example.com:443", "1.2.3.4:80", "[2001:db8::1]:5353"} {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatal(err)
		}
		b, err := tuicSerializeAddr(host, uint16(p))
		if err != nil {
			t.Fatal(err)
		}
		got, gotPort, err := tuicParseAddr(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != addr || int(gotPort) != p {
			t.Fatalf("round trip: got (%s, %d), want (%s, %d)", got, gotPort, addr, p)
		}
	}
}

func TestParseTUICUUID(t *testing.T) {
	want := [16]byte{0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	got, err := parseTUICUUID("12345678-abcd-ef01-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("uuid = %x, want %x", got, want)
	}
	if _, err := parseTUICUUID("not-a-uuid"); err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}

// mockTUICStream 用 bytes.Buffer 模拟 QUIC 流，记录写入的字节。
type mockTUICStream struct {
	net.Conn
	buf bytes.Buffer
	id  uint64
}

func (s *mockTUICStream) Write(b []byte) (int, error)        { return s.buf.Write(b) }
func (s *mockTUICStream) Read([]byte) (int, error)           { return 0, io.EOF }
func (s *mockTUICStream) Close() error                       { return nil }
func (s *mockTUICStream) StreamID() uint64                   { return s.id }
func (s *mockTUICStream) CloseWrite() error                  { return nil }
func (s *mockTUICStream) LocalAddr() net.Addr                { return nil }
func (s *mockTUICStream) RemoteAddr() net.Addr               { return nil }
func (s *mockTUICStream) SetDeadline(t time.Time) error      { return nil }
func (s *mockTUICStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *mockTUICStream) SetWriteDeadline(t time.Time) error { return nil }

func TestTUICStreamConnFirstWrite(t *testing.T) {
	ms := &mockTUICStream{}
	wc := &tuicStreamConn{Stream: ms, dest: "example.com:443"}

	if _, err := wc.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	wire := ms.buf.Bytes()
	if len(wire) < 2 {
		t.Fatal("short request")
	}
	if wire[0] != tuicVersion || wire[1] != tuicCmdConnect {
		t.Fatalf("header = %x %x", wire[0], wire[1])
	}
	addr, _, err := tuicParseAddr(wire[2:])
	if err != nil {
		t.Fatal(err)
	}
	if addr != "example.com:443" {
		t.Fatalf("addr = %s", addr)
	}
	if !bytes.HasSuffix(wire, []byte("hello")) {
		t.Fatal("payload missing")
	}

	// 第二次 Write 应直接透传，不带 Connect 头。
	ms.buf.Reset()
	if _, err := wc.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if ms.buf.String() != "world" {
		t.Fatalf("second write = %q", ms.buf.String())
	}
}

type mockDatagramConn struct {
	sent   [][]byte
	toRecv [][]byte
}

func (d *mockDatagramConn) SendDatagram(b []byte) error {
	d.sent = append(d.sent, append([]byte(nil), b...))
	return nil
}
func (d *mockDatagramConn) ReceiveDatagram(context.Context) ([]byte, error) {
	if len(d.toRecv) == 0 {
		return nil, io.EOF
	}
	b := d.toRecv[0]
	d.toRecv = d.toRecv[1:]
	return b, nil
}

func TestTUICPacketConnDatagram(t *testing.T) {
	dc := &mockDatagramConn{}
	pc := &tuicPacketConn{
		dc:        dc,
		sessionID: 0x1234,
		local:     &net.UDPAddr{},
		done:      make(chan struct{}),
	}

	if _, err := pc.WriteTo([]byte("payload"), &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443}); err != nil {
		t.Fatal(err)
	}
	wire := dc.sent[0]
	if wire[0] != tuicVersion || wire[1] != tuicCmdPacket {
		t.Fatalf("header = %x %x", wire[0], wire[1])
	}
	if binary.BigEndian.Uint16(wire[2:4]) != 0x1234 {
		t.Fatal("wrong session id")
	}
	if wire[6] != 1 || wire[7] != 0 {
		t.Fatal("wrong fragment fields")
	}
	if binary.BigEndian.Uint16(wire[8:10]) != uint16(len("payload")) {
		t.Fatal("wrong data length")
	}
	addr, _, err := tuicParseAddr(wire[10:])
	if err != nil {
		t.Fatal(err)
	}
	if addr != "1.2.3.4:443" {
		t.Fatalf("addr = %s", addr)
	}
	if !bytes.HasSuffix(wire, []byte("payload")) {
		t.Fatal("payload missing")
	}

	// 回包解析
	respAddr, _ := tuicSerializeAddr("5.6.7.8", 53)
	resp := []byte{tuicVersion, tuicCmdPacket, 0x12, 0x34, 0, 1, 1, 0, 0, 6}
	resp = append(resp, respAddr...)
	resp = append(resp, []byte("answer")...)
	dc.toRecv = append(dc.toRecv, resp)
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "answer" {
		t.Fatalf("data = %q", buf[:n])
	}
	if from.String() != "5.6.7.8:53" {
		t.Fatalf("from = %s", from)
	}
}

var _ quicproto.Stream = (*mockTUICStream)(nil)
