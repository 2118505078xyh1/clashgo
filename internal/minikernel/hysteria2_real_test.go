package minikernel

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestHyVarintRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 63, 64, 16383, 16384, 0x401, 1<<30 - 1, 1 << 30, 1<<62 - 1}
	for _, v := range values {
		got, err := hyVarintRoundTrip(v)
		if err != nil {
			t.Fatalf("varint %d: %v", v, err)
		}
		if got != v {
			t.Fatalf("varint round trip: got %d, want %d", got, v)
		}
	}
}

func TestBuildHyTCPRequest(t *testing.T) {
	addr := "example.com:443"
	b := buildHyTCPRequest(addr)
	r := &bytesReader{buf: b}

	frameType, err := hyReadVarint(r)
	if err != nil {
		t.Fatal(err)
	}
	if frameType != hyFrameTypeTCPRequest {
		t.Fatalf("frame type = 0x%x, want 0x401", frameType)
	}
	addrLen, err := hyReadVarint(r)
	if err != nil {
		t.Fatal(err)
	}
	if int(addrLen) != len(addr) {
		t.Fatalf("addrLen = %d, want %d", addrLen, len(addr))
	}
	if string(r.buf[:addrLen]) != addr {
		t.Fatalf("addr = %q, want %q", r.buf[:addrLen], addr)
	}
	r.buf = r.buf[addrLen:]
	padLen, err := hyReadVarint(r)
	if err != nil {
		t.Fatal(err)
	}
	if padLen == 0 || padLen > 4096 || uint64(len(r.buf)) != padLen {
		t.Fatalf("padLen = %d, remaining = %d", padLen, len(r.buf))
	}
}

func TestReadHyTCPResponse(t *testing.T) {
	build := func(status byte, msg string, padLen int) []byte {
		b := []byte{status}
		b = hyAppendVarint(b, uint64(len(msg)))
		b = append(b, msg...)
		b = hyAppendVarint(b, uint64(padLen))
		b = append(b, make([]byte, padLen)...)
		return b
	}

	for _, tc := range []struct {
		name    string
		wire    []byte
		wantOK  bool
		wantMsg string
	}{
		{"ok", build(0, "", 32), true, ""},
		{"ok-with-message", build(0, "hello", 64), true, "hello"},
		{"error", build(1, "dial failed", 16), false, "dial failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, msg, err := readHyTCPResponse(bufio.NewReader(bytes.NewReader(tc.wire)))
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.wantOK || msg != tc.wantMsg {
				t.Fatalf("got (%v, %q), want (%v, %q)", ok, msg, tc.wantOK, tc.wantMsg)
			}
		})
	}

	if _, _, err := readHyTCPResponse(bufio.NewReader(strings.NewReader(""))); err == nil {
		t.Fatal("expected error on empty response")
	}
}

func TestHyUDPMessageRoundTrip(t *testing.T) {
	msg := &hyUDPMessage{
		SessionID: 0x12345678,
		PacketID:  0xabcd,
		FragID:    0,
		FragCount: 1,
		Addr:      "1.2.3.4:443",
		Data:      []byte("hello udp"),
	}
	wire := msg.serialize()
	got, err := parseHyUDPMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != msg.SessionID || got.PacketID != msg.PacketID ||
		got.FragID != msg.FragID || got.FragCount != msg.FragCount ||
		got.Addr != msg.Addr || !bytes.Equal(got.Data, msg.Data) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, msg)
	}
}

func TestHyUDPMessageRejectsBadInput(t *testing.T) {
	for _, wire := range [][]byte{
		{},
		make([]byte, 8),
		append(make([]byte, 8), 0xff), // addrLen too large / truncated
	} {
		if _, err := parseHyUDPMessage(wire); err == nil {
			t.Fatalf("expected error for %x", wire)
		}
	}
}
