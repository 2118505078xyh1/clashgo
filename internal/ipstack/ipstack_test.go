package ipstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// testTimeout is generous on purpose: all waits are channel/timer based (no
// polling sleeps), so a timeout means a real bug rather than a scheduling
// hiccup.
const testTimeout = 3 * time.Second

var (
	testClientIP = [4]byte{192, 0, 2, 1}
	testServerIP = [4]byte{192, 0, 2, 2}
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// captureDevice is a TUN stand-in. Reads are fed through readCh; every write
// is copied into written (for snapshots) and signalled on writtenCh so tests
// can wait without sleeping. Close unblocks Start without closing readCh,
// which tests still need to be able to send on.
type captureDevice struct {
	mu        sync.Mutex
	written   [][]byte
	writtenCh chan []byte
	readCh    chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
	writeErr  error
}

func newCaptureDevice() *captureDevice {
	return &captureDevice{
		writtenCh: make(chan []byte, 256),
		readCh:    make(chan []byte, 64),
		closeCh:   make(chan struct{}),
	}
}

func (d *captureDevice) setWriteErr(err error) {
	d.mu.Lock()
	d.writeErr = err
	d.mu.Unlock()
}

func (d *captureDevice) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	d.mu.Lock()
	if d.writeErr != nil {
		d.mu.Unlock()
		return 0, d.writeErr
	}
	d.written = append(d.written, cp)
	d.mu.Unlock()
	select {
	case d.writtenCh <- cp:
	default: // buffer is intentionally large; never block the stack
	}
	return len(p), nil
}

func (d *captureDevice) Read(p []byte) (int, error) {
	select {
	case b, ok := <-d.readCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, b), nil
	case <-d.closeCh:
		return 0, io.EOF
	}
}

func (d *captureDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closeCh) })
	return nil
}

func (d *captureDevice) feed(t *testing.T, pkt []byte) {
	t.Helper()
	select {
	case d.readCh <- append([]byte(nil), pkt...):
	case <-time.After(testTimeout):
		t.Fatal("timeout feeding packet to device")
	}
}

func (d *captureDevice) waitWritten(t *testing.T, n int, timeout time.Duration) [][]byte {
	t.Helper()
	out := make([][]byte, 0, n)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(out) < n {
		select {
		case p := <-d.writtenCh:
			out = append(out, p)
		case <-timer.C:
			t.Fatalf("timeout waiting for %d written packet(s); got %d", n, len(out))
		}
	}
	return out
}

func (d *captureDevice) nextWritten(t *testing.T) []byte {
	t.Helper()
	return d.waitWritten(t, 1, testTimeout)[0]
}

func (d *captureDevice) snapshot() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.written))
	copy(out, d.written)
	return out
}

// expectQuiet fails if any additional packet shows up within quiet.
func (d *captureDevice) expectQuiet(t *testing.T, quiet time.Duration) {
	t.Helper()
	select {
	case p := <-d.writtenCh:
		t.Fatalf("unexpected extra packet written: % x", p)
	case <-time.After(quiet):
	}
}

type tcpCall struct {
	ctx              context.Context
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
	conn             net.Conn
}

type udpCall struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
	payload          []byte
}

// testHandler records callbacks. When echo is true, NewTCP starts the
// read/write echo loop in its own goroutine as a real upper layer would. The
// loop waits on echoGate before replying so tests can deterministically
// observe the stack's ACK before the echo segment is emitted (otherwise the
// stack's own ACK and the echo race each other for the write mutex).
type testHandler struct {
	tcpCh chan tcpCall
	udpCh chan udpCall
	echo  bool

	echoGate chan struct{}
	gateOnce sync.Once
}

func newTestHandler(echo bool) *testHandler {
	return &testHandler{
		tcpCh:    make(chan tcpCall, 8),
		udpCh:    make(chan udpCall, 16),
		echo:     echo,
		echoGate: make(chan struct{}),
	}
}

func (h *testHandler) allowEcho() { h.gateOnce.Do(func() { close(h.echoGate) }) }

func (h *testHandler) NewTCP(ctx context.Context, srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, conn net.Conn) {
	call := tcpCall{ctx: ctx, srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, conn: conn}
	select {
	case h.tcpCh <- call:
	default:
	}
	if !h.echo {
		return
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				<-h.echoGate
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

func (h *testHandler) NewUDP(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, payload []byte) {
	call := udpCall{
		srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort,
		payload: append([]byte(nil), payload...),
	}
	select {
	case h.udpCh <- call:
	default:
	}
}

func (h *testHandler) nextTCP(t *testing.T) tcpCall {
	t.Helper()
	select {
	case c := <-h.tcpCh:
		return c
	case <-time.After(testTimeout):
		t.Fatal("timeout waiting for Handler.NewTCP")
		return tcpCall{}
	}
}

func (h *testHandler) nextUDP(t *testing.T) udpCall {
	t.Helper()
	select {
	case c := <-h.udpCh:
		return c
	case <-time.After(testTimeout):
		t.Fatal("timeout waiting for Handler.NewUDP")
		return udpCall{}
	}
}

func (h *testHandler) expectNoUDP(t *testing.T, quiet time.Duration) {
	t.Helper()
	select {
	case c := <-h.udpCh:
		t.Fatalf("unexpected UDP callback: %+v", c)
	case <-time.After(quiet):
	}
}

// newStartedStack runs the real receive loop in a goroutine and makes sure it
// is drained on test completion.
func newStartedStack(t *testing.T, cfg Config, h Handler) (*Stack, *captureDevice) {
	t.Helper()
	dev := newCaptureDevice()
	s := New(cfg, h)
	// Publish the device before Start's goroutine can race with an immediate
	// SendUDP/handlePacket call from the test body. Start re-assigns the same
	// device under the lock, which is harmless.
	s.mu.Lock()
	s.device = dev
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.Start(dev)
		close(done)
	}()
	t.Cleanup(func() {
		s.Close()
		select {
		case <-done:
		case <-time.After(testTimeout):
			t.Error("Start did not return after Close")
		}
	})
	return s, dev
}

// ---------------------------------------------------------------------------
// Packet builders / parsers
// ---------------------------------------------------------------------------

func recomputeHeaderChecksum(pkt []byte) {
	ihl := int(pkt[0]&0x0f) * 4
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ihl]))
}

func buildTCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	seg := make([]byte, tcpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = 5 << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[tcpHeaderLen:], payload)
	binary.BigEndian.PutUint16(seg[16:18], tcpChecksum(srcIP, dstIP, seg))
	return buildIPv4(protoTCP, srcIP, dstIP, seg, 0x1234)
}

func buildUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	seg := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	copy(seg[udpHeaderLen:], payload)
	binary.BigEndian.PutUint16(seg[6:8], udpChecksum(srcIP, dstIP, seg))
	return buildIPv4(protoUDP, srcIP, dstIP, seg, 0x1234)
}

func buildICMPEchoRequest(id, seq uint16, data []byte) []byte {
	msg := make([]byte, 8+len(data))
	msg[0], msg[1] = 8, 0 // Echo Request
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], data)
	binary.BigEndian.PutUint16(msg[2:4], checksum(msg))
	return buildIPv4(protoICMP, testClientIP, testServerIP, msg, 0x4242)
}

func parseIPv4OrFail(t *testing.T, pkt []byte) ipv4Packet {
	t.Helper()
	p, ok := parseIPv4(pkt)
	if !ok {
		t.Fatalf("parseIPv4 failed for packet % x", pkt)
	}
	if got := checksum(pkt[:p.ihl]); got != 0 {
		t.Fatalf("emitted IPv4 header checksum = 0x%04x, want 0", got)
	}
	return p
}

type parsedTCP struct {
	srcPort, dstPort uint16
	seq, ack         uint32
	flags            uint8
	payload          []byte
}

func parseTCPOrFail(t *testing.T, p ipv4Packet) parsedTCP {
	t.Helper()
	if p.proto != protoTCP {
		t.Fatalf("protocol = %d, want TCP(%d)", p.proto, protoTCP)
	}
	seg := p.payload
	if len(seg) < tcpHeaderLen {
		t.Fatalf("short TCP segment: %d bytes", len(seg))
	}
	off := int((seg[12] >> 4) * 4)
	if off < tcpHeaderLen || off > len(seg) {
		t.Fatalf("invalid TCP data offset %d (segment length %d)", off, len(seg))
	}
	// The checksum field must be zeroed before recomputing the pseudo-header
	// checksum.
	cp := append([]byte(nil), seg...)
	stored := binary.BigEndian.Uint16(cp[16:18])
	binary.BigEndian.PutUint16(cp[16:18], 0)
	if want := tcpChecksum(p.src, p.dst, cp); want != stored {
		t.Fatalf("TCP checksum = 0x%04x, want 0x%04x", stored, want)
	}
	return parsedTCP{
		srcPort: binary.BigEndian.Uint16(seg[0:2]),
		dstPort: binary.BigEndian.Uint16(seg[2:4]),
		seq:     binary.BigEndian.Uint32(seg[4:8]),
		ack:     binary.BigEndian.Uint32(seg[8:12]),
		flags:   seg[13],
		payload: append([]byte(nil), seg[off:]...),
	}
}

type parsedUDP struct {
	srcPort, dstPort uint16
	length           int
	payload          []byte
}

func parseUDPOrFail(t *testing.T, p ipv4Packet) parsedUDP {
	t.Helper()
	if p.proto != protoUDP {
		t.Fatalf("protocol = %d, want UDP(%d)", p.proto, protoUDP)
	}
	seg := p.payload
	if len(seg) < udpHeaderLen {
		t.Fatalf("short UDP datagram: %d bytes", len(seg))
	}
	cp := append([]byte(nil), seg...)
	stored := binary.BigEndian.Uint16(cp[6:8])
	binary.BigEndian.PutUint16(cp[6:8], 0)
	// A zero on the wire is the "checksum disabled" encoding; otherwise the
	// pseudo-header checksum must validate.
	if stored != 0 {
		if want := udpChecksum(p.src, p.dst, cp); want != stored {
			t.Fatalf("UDP checksum = 0x%04x, want 0x%04x", stored, want)
		}
	}
	return parsedUDP{
		srcPort: binary.BigEndian.Uint16(seg[0:2]),
		dstPort: binary.BigEndian.Uint16(seg[2:4]),
		length:  int(binary.BigEndian.Uint16(seg[4:6])),
		payload: append([]byte(nil), seg[udpHeaderLen:]...),
	}
}

// verifyTransportChecksum computes the Internet checksum over the IPv4 pseudo
// header plus a segment whose checksum field is already filled in; a correct
// segment yields zero.
func verifyTransportChecksum(t *testing.T, src, dst [4]byte, proto uint8, seg []byte) {
	t.Helper()
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	if got := checksum(pseudo); got != 0 {
		t.Fatalf("pseudo-header checksum verification = 0x%04x, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// 1+2. IPv4 header round trip, parser edge cases and checksums
// ---------------------------------------------------------------------------

func TestBuildParseIPv4RoundTrip(t *testing.T) {
	src := [4]byte{10, 1, 2, 3}
	dst := [4]byte{10, 4, 5, 6}
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	pkt := buildIPv4(protoUDP, src, dst, payload, 0x1234)

	if len(pkt) != ipHeaderLen+len(payload) {
		t.Fatalf("packet length = %d, want %d", len(pkt), ipHeaderLen+len(payload))
	}
	p, ok := parseIPv4(pkt)
	if !ok {
		t.Fatal("parseIPv4 rejected a packet produced by buildIPv4")
	}
	if p.version != 4 || p.ihl != ipHeaderLen {
		t.Errorf("version/ihl = %d/%d, want 4/%d", p.version, p.ihl, ipHeaderLen)
	}
	if p.tos != 0 {
		t.Errorf("tos = %d, want 0", p.tos)
	}
	if p.totalLen != len(pkt) {
		t.Errorf("totalLen = %d, want %d", p.totalLen, len(pkt))
	}
	if p.id != 0x1234 {
		t.Errorf("id = 0x%04x, want 0x1234", p.id)
	}
	if p.flagsFrag != 0x4000 {
		t.Errorf("flagsFrag = 0x%04x, want 0x4000 (DF)", p.flagsFrag)
	}
	if p.ttl != 64 {
		t.Errorf("ttl = %d, want 64", p.ttl)
	}
	if p.proto != protoUDP {
		t.Errorf("proto = %d, want %d", p.proto, protoUDP)
	}
	if p.src != src || p.dst != dst {
		t.Errorf("addresses = %v -> %v, want %v -> %v", p.src, p.dst, src, dst)
	}
	if !bytes.Equal(p.payload, payload) {
		t.Errorf("payload = % x, want % x", p.payload, payload)
	}
	// The standard Internet checksum of a header carrying its own checksum is
	// zero.
	if got := checksum(pkt[:ipHeaderLen]); got != 0 {
		t.Errorf("header checksum verification = 0x%04x, want 0", got)
	}
	// Corrupting any header byte must be detectable.
	corrupt := append([]byte(nil), pkt...)
	corrupt[8] ^= 0xff
	if got := checksum(corrupt[:ipHeaderLen]); got == 0 {
		t.Error("corrupted header still verified as valid")
	}
}

func TestParseIPv4EdgeCases(t *testing.T) {
	base := buildIPv4(protoTCP, testClientIP, testServerIP, []byte{1, 2, 3, 4}, 7)

	t.Run("too short", func(t *testing.T) {
		if _, ok := parseIPv4(base[:ipHeaderLen-1]); ok {
			t.Fatal("accepted a packet shorter than the fixed header")
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		p := append([]byte(nil), base...)
		p[0] = 0x65
		if _, ok := parseIPv4(p); ok {
			t.Fatal("accepted a non-IPv4 version nibble")
		}
	})
	t.Run("ihl below minimum", func(t *testing.T) {
		p := append([]byte(nil), base...)
		p[0] = 0x40
		if _, ok := parseIPv4(p); ok {
			t.Fatal("accepted ihl=0")
		}
	})
	t.Run("ihl beyond packet", func(t *testing.T) {
		p := append([]byte(nil), base...)
		p[0] = 0x4f
		if _, ok := parseIPv4(p); ok {
			t.Fatal("accepted ihl=60 for a 24-byte packet")
		}
	})
	t.Run("options header", func(t *testing.T) {
		p := append([]byte(nil), base[:ipHeaderLen]...)
		p = append(p, 0xaa, 0xbb, 0xcc, 0xdd) // four bytes of options
		p = append(p, base[ipHeaderLen:]...)
		p[0] = 0x46 // ihl = 6 words = 24 bytes
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		recomputeHeaderChecksum(p)
		got, ok := parseIPv4(p)
		if !ok {
			t.Fatal("rejected packet with options")
		}
		if got.ihl != 24 {
			t.Errorf("ihl = %d, want 24", got.ihl)
		}
		if !bytes.Equal(got.payload, base[ipHeaderLen:]) {
			t.Errorf("payload = % x, want % x", got.payload, base[ipHeaderLen:])
		}
	})
	t.Run("inconsistent totalLen falls back to capture length", func(t *testing.T) {
		p := append([]byte(nil), base...)
		binary.BigEndian.PutUint16(p[2:4], 0)
		got, ok := parseIPv4(p)
		if !ok {
			t.Fatal("rejected packet with inconsistent totalLen")
		}
		if got.totalLen != len(p) {
			t.Errorf("totalLen = %d, want %d", got.totalLen, len(p))
		}
		if len(got.payload) != 4 {
			t.Errorf("payload length = %d, want 4", len(got.payload))
		}
	})
}

func TestChecksumRFC1071(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{"empty", nil, 0xffff},
		{"zero and all ones", []byte{0x00, 0x00, 0xff, 0xff}, 0x0000},
		{"all ones twice", []byte{0xff, 0xff, 0xff, 0xff}, 0x0000},
		{"small sum", []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x03}, 0xfff9},
		{"odd length pads with zero", []byte{0x01}, 0xfeff},
		{"odd length three bytes", []byte{0x01, 0x02, 0x03}, 0xfbfd},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checksum(tc.data); got != tc.want {
				t.Fatalf("checksum(% x) = 0x%04x, want 0x%04x", tc.data, got, tc.want)
			}
		})
	}

	// End-to-end invariant: a header containing its own computed checksum
	// verifies as zero (also asserted by the IPv4 round-trip test).
	pkt := buildIPv4(protoICMP, testClientIP, testServerIP, []byte{1}, 1)
	if got := checksum(pkt[:ipHeaderLen]); got != 0 {
		t.Fatalf("built header verification = 0x%04x, want 0", got)
	}
}

func TestTransportChecksums(t *testing.T) {
	src, dst := testClientIP, testServerIP

	t.Run("tcp", func(t *testing.T) {
		seg := make([]byte, tcpHeaderLen+5)
		binary.BigEndian.PutUint16(seg[0:2], 12345)
		binary.BigEndian.PutUint16(seg[2:4], 80)
		binary.BigEndian.PutUint32(seg[4:8], 100)
		binary.BigEndian.PutUint32(seg[8:12], 200)
		seg[12] = 5 << 4
		seg[13] = flagPSH | flagACK
		copy(seg[tcpHeaderLen:], "abcde")
		c := tcpChecksum(src, dst, seg)
		binary.BigEndian.PutUint16(seg[16:18], c)
		verifyTransportChecksum(t, src, dst, protoTCP, seg)
	})

	t.Run("udp", func(t *testing.T) {
		seg := make([]byte, udpHeaderLen+3)
		binary.BigEndian.PutUint16(seg[0:2], 53)
		binary.BigEndian.PutUint16(seg[2:4], 53000)
		binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
		copy(seg[udpHeaderLen:], "xyz")
		c := udpChecksum(src, dst, seg)
		binary.BigEndian.PutUint16(seg[6:8], c)
		verifyTransportChecksum(t, src, dst, protoUDP, seg)
	})

	t.Run("pseudo header addresses and protocol matter", func(t *testing.T) {
		seg := make([]byte, udpHeaderLen+1)
		seg[udpHeaderLen] = 0x42
		c := udpChecksum(src, dst, seg)
		other := dst
		other[3]++
		if c == udpChecksum(other, dst, seg) {
			t.Fatal("changing the pseudo-header source did not change the checksum")
		}
		if c == udpChecksum(src, other, seg) {
			t.Fatal("changing the pseudo-header destination did not change the checksum")
		}
	})
}

// ---------------------------------------------------------------------------
// 3. ICMP echo
// ---------------------------------------------------------------------------

func TestHandleICMPEcho(t *testing.T) {
	_, dev := newStartedStack(t, Config{}, nil)

	reqData := []byte("0123456789")
	req := buildICMPEchoRequest(0xabcd, 0x0007, reqData)
	dev.feed(t, req)

	replyPkt := dev.nextWritten(t)
	ip := parseIPv4OrFail(t, replyPkt)
	if ip.proto != protoICMP {
		t.Fatalf("reply proto = %d, want ICMP(%d)", ip.proto, protoICMP)
	}
	// Source and destination must be swapped relative to the request.
	if ip.src != testServerIP || ip.dst != testClientIP {
		t.Errorf("reply addresses = %v -> %v, want %v -> %v", ip.src, ip.dst, testServerIP, testClientIP)
	}
	msg := ip.payload
	if len(msg) < 8 {
		t.Fatalf("ICMP reply length = %d, want >= 8", len(msg))
	}
	if msg[0] != 0 || msg[1] != 0 {
		t.Errorf("ICMP type/code = %d/%d, want Echo Reply 0/0", msg[0], msg[1])
	}
	if got := checksum(msg); got != 0 {
		t.Errorf("ICMP reply checksum verification = 0x%04x, want 0", got)
	}
	if id := binary.BigEndian.Uint16(msg[4:6]); id != 0xabcd {
		t.Errorf("ICMP id = 0x%04x, want 0xabcd", id)
	}
	if seq := binary.BigEndian.Uint16(msg[6:8]); seq != 0x0007 {
		t.Errorf("ICMP seq = 0x%04x, want 0x0007", seq)
	}
	if !bytes.Equal(msg[8:], reqData) {
		t.Errorf("ICMP reply data = % x, want % x", msg[8:], reqData)
	}
	dev.expectQuiet(t, 100*time.Millisecond)

	// Non-echo ICMP messages and malformed echo messages are ignored.
	s2, dev2 := newStartedStack(t, Config{}, nil)
	_ = s2
	short := buildIPv4(protoICMP, testClientIP, testServerIP, []byte{8, 0, 0, 0}, 1)
	dev2.feed(t, short)
	notEcho := buildIPv4(protoICMP, testClientIP, testServerIP, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 2)
	dev2.feed(t, notEcho)
	dev2.expectQuiet(t, 100*time.Millisecond)
}

// ---------------------------------------------------------------------------
// Dispatch guard rails
// ---------------------------------------------------------------------------

func TestHandlePacketIgnoresInvalid(t *testing.T) {
	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{}, h)

	dev.feed(t, []byte{0x45, 0x00})                                               // truncated IP
	dev.feed(t, buildIPv4(99, testClientIP, testServerIP, []byte{1, 2, 3, 4}, 1)) // unknown protocol
	frag := buildUDPPacket(testClientIP, testServerIP, 1000, 2000, []byte("frag"))
	frag[6] |= 0x01 // non-first fragment: payload is not a complete UDP header
	dev.feed(t, frag)
	shortUDP := buildIPv4(protoUDP, testClientIP, testServerIP, []byte{1, 2, 3}, 2)
	dev.feed(t, shortUDP)
	shortTCP := buildIPv4(protoTCP, testClientIP, testServerIP, []byte{1, 2, 3}, 3)
	dev.feed(t, shortTCP)
	badOff := buildTCPPacket(testClientIP, testServerIP, 1, 2, 1, 0, flagACK, []byte("x"))
	badOff[ipHeaderLen+12] = 0x00 // data offset below the minimum
	dev.feed(t, badOff)
	badOff2 := buildTCPPacket(testClientIP, testServerIP, 1, 2, 1, 0, flagACK, []byte("x"))
	badOff2[ipHeaderLen+12] = 0xf0 // data offset beyond the segment
	dev.feed(t, badOff2)

	dev.expectQuiet(t, 150*time.Millisecond)
	h.expectNoUDP(t, 50*time.Millisecond)
}

// ---------------------------------------------------------------------------
// 4. UDP dispatch
// ---------------------------------------------------------------------------

func TestHandleUDPDispatch(t *testing.T) {
	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{}, h)

	payload := []byte("hello UDP world")
	dev.feed(t, buildUDPPacket(testClientIP, testServerIP, 5353, 8080, payload))

	call := h.nextUDP(t)
	if call.srcIP != testClientIP || call.dstIP != testServerIP {
		t.Errorf("UDP addresses = %v -> %v, want %v -> %v", call.srcIP, call.dstIP, testClientIP, testServerIP)
	}
	if call.srcPort != 5353 || call.dstPort != 8080 {
		t.Errorf("UDP ports = %d -> %d, want 5353 -> 8080", call.srcPort, call.dstPort)
	}
	if !bytes.Equal(call.payload, payload) {
		t.Errorf("UDP payload = %q, want %q", call.payload, payload)
	}
	// The handler must receive a copy, not a view into the device buffer.
	call.payload[0] ^= 0xff
	if payload[0] == call.payload[0] {
		t.Error("handler payload aliases the caller's buffer")
	}
	dev.expectQuiet(t, 50*time.Millisecond)
}

// ---------------------------------------------------------------------------
// 5. SendUDP
// ---------------------------------------------------------------------------

func TestSendUDP(t *testing.T) {
	s, dev := newStartedStack(t, Config{}, nil)

	payload := []byte("reply datagram")
	if err := s.SendUDP(testServerIP, 9999, testClientIP, 8888, payload, true); err != nil {
		t.Fatalf("SendUDP(with checksum) failed: %v", err)
	}
	pkt := dev.nextWritten(t)
	ip := parseIPv4OrFail(t, pkt)
	if ip.src != testServerIP || ip.dst != testClientIP || ip.proto != protoUDP {
		t.Errorf("emitted IPv4 = %v -> %v proto %d", ip.src, ip.dst, ip.proto)
	}
	u := parseUDPOrFail(t, ip)
	if u.srcPort != 9999 || u.dstPort != 8888 {
		t.Errorf("UDP ports = %d -> %d, want 9999 -> 8888", u.srcPort, u.dstPort)
	}
	if u.length != udpHeaderLen+len(payload) {
		t.Errorf("UDP length = %d, want %d", u.length, udpHeaderLen+len(payload))
	}
	if !bytes.Equal(u.payload, payload) {
		t.Errorf("UDP payload = %q, want %q", u.payload, payload)
	}
	if csum := binary.BigEndian.Uint16(ip.payload[6:8]); csum == 0 {
		t.Error("checksum=true emitted a zero UDP checksum")
	}
	idWithChecksum := ip.id

	if err := s.SendUDP(testServerIP, 9999, testClientIP, 8888, payload, false); err != nil {
		t.Fatalf("SendUDP(no checksum) failed: %v", err)
	}
	pkt2 := dev.nextWritten(t)
	ip2 := parseIPv4OrFail(t, pkt2)
	u2 := parseUDPOrFail(t, ip2)
	if csum := binary.BigEndian.Uint16(ip2.payload[6:8]); csum != 0 {
		t.Errorf("checksum=false emitted checksum 0x%04x, want 0", csum)
	}
	if !bytes.Equal(u2.payload, payload) || u2.srcPort != 9999 || u2.dstPort != 8888 {
		t.Error("second datagram header/payload mismatch")
	}
	if ip2.id == idWithChecksum {
		t.Error("IP ID did not advance between SendUDP calls")
	}
	dev.expectQuiet(t, 50*time.Millisecond)
}

// ---------------------------------------------------------------------------
// 6. TCP three-way handshake, data echo and FIN
// ---------------------------------------------------------------------------

func TestTCPThreeWayHandshakeAndEcho(t *testing.T) {
	const clientISN uint32 = 1000

	h := newTestHandler(true)
	_, dev := newStartedStack(t, Config{}, h)

	// SYN -> SYN-ACK
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 12345, 80, clientISN, 0, flagSYN, nil))
	ip := parseIPv4OrFail(t, dev.nextWritten(t))
	if ip.src != testServerIP || ip.dst != testClientIP {
		t.Errorf("SYN-ACK addresses = %v -> %v", ip.src, ip.dst)
	}
	sa := parseTCPOrFail(t, ip)
	if sa.srcPort != 80 || sa.dstPort != 12345 {
		t.Errorf("SYN-ACK ports = %d -> %d, want 80 -> 12345", sa.srcPort, sa.dstPort)
	}
	if sa.flags != flagSYN|flagACK {
		t.Errorf("SYN-ACK flags = 0x%02x, want SYN|ACK (0x%02x)", sa.flags, flagSYN|flagACK)
	}
	if sa.ack != clientISN+1 {
		t.Errorf("SYN-ACK ack = %d, want %d", sa.ack, clientISN+1)
	}
	if len(sa.payload) != 0 {
		t.Errorf("SYN-ACK carries %d payload bytes", len(sa.payload))
	}
	serverISN := sa.seq

	// A retransmitted SYN must produce a SYN-ACK with the same sequence/ack.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 12345, 80, clientISN, 0, flagSYN, nil))
	rs := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if rs.seq != serverISN || rs.ack != clientISN+1 || rs.flags != flagSYN|flagACK {
		t.Errorf("retransmitted SYN response = seq %d ack %d flags 0x%02x", rs.seq, rs.ack, rs.flags)
	}

	// ACK completes the handshake and triggers Handler.NewTCP.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 12345, 80, clientISN+1, serverISN+1, flagACK, nil))
	call := h.nextTCP(t)
	if call.ctx == nil || call.conn == nil {
		t.Fatal("NewTCP got a nil context or conn")
	}
	if call.srcIP != testClientIP || call.dstIP != testServerIP || call.srcPort != 12345 || call.dstPort != 80 {
		t.Errorf("NewTCP endpoint = %v:%d -> %v:%d", call.srcIP, call.srcPort, call.dstIP, call.dstPort)
	}
	if call.conn.LocalAddr().String() != "192.0.2.2:80" || call.conn.RemoteAddr().String() != "192.0.2.1:12345" {
		t.Errorf("conn addresses = %s -> %s", call.conn.LocalAddr(), call.conn.RemoteAddr())
	}

	// PSH+ACK with data: the stack acknowledges it and the upper layer reads it.
	payload := []byte("ping over tcp")
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 12345, 80, clientISN+1, serverISN+1, flagPSH|flagACK, payload))

	ackPkt := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if ackPkt.flags != flagACK || len(ackPkt.payload) != 0 {
		t.Errorf("data ACK flags/payload = 0x%02x/%q, want ACK with no payload", ackPkt.flags, ackPkt.payload)
	}
	if ackPkt.ack != clientISN+1+uint32(len(payload)) {
		t.Errorf("data ACK ack = %d, want %d", ackPkt.ack, clientISN+1+uint32(len(payload)))
	}
	if ackPkt.seq != serverISN+1 {
		t.Errorf("data ACK seq = %d, want %d", ackPkt.seq, serverISN+1)
	}

	// Release the handler's echo loop and verify the emitted data segment.
	h.allowEcho()
	echo := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if echo.flags != flagPSH|flagACK {
		t.Errorf("echo flags = 0x%02x, want PSH|ACK", echo.flags)
	}
	if !bytes.Equal(echo.payload, payload) {
		t.Errorf("echo payload = %q, want %q", echo.payload, payload)
	}
	if echo.srcPort != 80 || echo.dstPort != 12345 {
		t.Errorf("echo ports = %d -> %d", echo.srcPort, echo.dstPort)
	}
	if echo.seq != serverISN+1 {
		t.Errorf("echo seq = %d, want %d", echo.seq, serverISN+1)
	}
	if echo.ack != clientISN+1+uint32(len(payload)) {
		t.Errorf("echo ack = %d, want %d", echo.ack, clientISN+1+uint32(len(payload)))
	}

	// FIN -> FIN-ACK, then the connection is forgotten.
	finSeq := clientISN + 1 + uint32(len(payload))
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 12345, 80, finSeq, serverISN+1+uint32(len(payload)), flagFIN|flagACK, nil))
	fin := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if fin.flags != flagFIN|flagACK {
		t.Errorf("FIN response flags = 0x%02x, want FIN|ACK", fin.flags)
	}
	if fin.ack != finSeq+1 {
		t.Errorf("FIN response ack = %d, want %d", fin.ack, finSeq+1)
	}
	if fin.seq != serverISN+1+uint32(len(payload)) {
		t.Errorf("FIN response seq = %d, want %d", fin.seq, serverISN+1+uint32(len(payload)))
	}
	if len(fin.payload) != 0 {
		t.Errorf("FIN response carries %d payload bytes", len(fin.payload))
	}
	// Closing an already FIN-closed conn must not emit a second FIN.
	_ = call.conn.Close()
	dev.expectQuiet(t, 150*time.Millisecond)
}

// ---------------------------------------------------------------------------
// 7. TCP MTU fragmentation
// ---------------------------------------------------------------------------

func TestTCPFragmentation(t *testing.T) {
	const (
		mtu        = 100
		clientISN  = uint32(5000)
		maxPayload = mtu - ipHeaderLen - tcpHeaderLen // 60
	)

	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{MTU: mtu}, h)

	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 40000, 443, clientISN, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	serverISN := sa.seq
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 40000, 443, clientISN+1, serverISN+1, flagACK, nil))
	call := h.nextTCP(t)
	baselineWrites := len(dev.snapshot()) // includes the SYN-ACK

	data := bytes.Repeat([]byte("0123456789"), 50) // 500 bytes
	n, err := call.conn.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("conn.Write = (%d, %v), want (%d, nil)", n, err, len(data))
	}

	wantSegments := (len(data) + maxPayload - 1) / maxPayload
	packets := dev.waitWritten(t, wantSegments, testTimeout)
	var reassembled []byte
	wantSeq := serverISN + 1
	for i, pkt := range packets {
		ip := parseIPv4OrFail(t, pkt)
		if ip.totalLen != len(pkt) || ip.totalLen > mtu {
			t.Errorf("segment %d IPv4 totalLen = %d (packet %d, MTU %d)", i, ip.totalLen, len(pkt), mtu)
		}
		seg := parseTCPOrFail(t, ip)
		if len(seg.payload) == 0 || len(seg.payload) > maxPayload {
			t.Errorf("segment %d payload length = %d, want 1..%d", i, len(seg.payload), maxPayload)
		}
		if seg.flags != flagPSH|flagACK {
			t.Errorf("segment %d flags = 0x%02x, want PSH|ACK", i, seg.flags)
		}
		if seg.seq != wantSeq {
			t.Errorf("segment %d seq = %d, want %d", i, seg.seq, wantSeq)
		}
		if seg.ack != clientISN+1 {
			t.Errorf("segment %d ack = %d, want %d", i, seg.ack, clientISN+1)
		}
		wantSeq += uint32(len(seg.payload))
		reassembled = append(reassembled, seg.payload...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Fatalf("reassembled %d bytes differ from the %d written bytes", len(reassembled), len(data))
	}
	if got := len(dev.snapshot()) - baselineWrites; got != wantSegments {
		t.Errorf("conn.Write produced %d writes, want %d", got, wantSegments)
	}
	dev.expectQuiet(t, 100*time.Millisecond)

	// Writing after the virtual connection was closed must fail.
	_ = call.conn.Close() // emits a FIN; consume it so the device stays in sync
	dev.nextWritten(t)
	if _, err := call.conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after Close returned %v, want net.ErrClosed", err)
	}
}

// ---------------------------------------------------------------------------
// 8. pipeConn behaviour
// ---------------------------------------------------------------------------

type readResult struct {
	n    int
	err  error
	data []byte
}

func TestPipeConnBlockingReadAndWakeup(t *testing.T) {
	c := newPipeConn()
	res := make(chan readResult, 1)
	go func() {
		b := make([]byte, 8)
		n, err := c.Read(b)
		res <- readResult{n: n, err: err, data: append([]byte(nil), b[:n]...)}
	}()

	select {
	case r := <-res:
		t.Fatalf("Read returned before any data: %+v", r)
	case <-time.After(30 * time.Millisecond):
	}

	c.pushData([]byte("abc"))
	select {
	case r := <-res:
		if r.err != nil || string(r.data) != "abc" {
			t.Fatalf("Read after pushData = (%d, %v, %q)", r.n, r.err, r.data)
		}
	case <-time.After(testTimeout):
		t.Fatal("blocked Read did not wake after pushData")
	}

	// Data is buffered and can be read in pieces.
	c.pushData([]byte("defgh"))
	small := make([]byte, 2)
	if n, err := c.Read(small); err != nil || n != 2 || string(small) != "de" {
		t.Fatalf("partial Read = (%d, %v, %q), want (2, nil, \"de\")", n, err, small)
	}
	rest := make([]byte, 8)
	if n, err := c.Read(rest); err != nil || n != 3 || string(rest[:n]) != "fgh" {
		t.Fatalf("remaining Read = (%d, %v, %q), want (3, nil, \"fgh\")", n, err, rest[:n])
	}

	c.shutdown()
	if n, err := c.Read(make([]byte, 4)); n != 0 || err != io.EOF {
		t.Fatalf("Read after shutdown = (%d, %v), want (0, EOF)", n, err)
	}
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Errorf("zero-length Read = (%d, %v), want (0, nil)", n, err)
	}
}

func TestPipeConnReadDeadline(t *testing.T) {
	t.Run("past deadline", func(t *testing.T) {
		c := newPipeConn()
		if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := c.Read(make([]byte, 4))
		if n != 0 || err == nil {
			t.Fatalf("Read = (%d, %v), want timeout", n, err)
		}
		ne, ok := err.(net.Error)
		if !ok || !ne.Timeout() {
			t.Fatalf("error %v does not implement net.Error.Timeout", err)
		}
	})

	t.Run("deadline wakes a blocked reader", func(t *testing.T) {
		c := newPipeConn()
		res := make(chan error, 1)
		go func() {
			_, err := c.Read(make([]byte, 4))
			res <- err
		}()
		select {
		case err := <-res:
			t.Fatalf("Read returned unexpectedly: %v", err)
		case <-time.After(30 * time.Millisecond):
		}

		if err := c.SetReadDeadline(time.Now().Add(80 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-res:
			ne, ok := err.(net.Error)
			if !ok || !ne.Timeout() {
				t.Fatalf("error %v is not a net.Error timeout", err)
			}
		case <-time.After(testTimeout):
			t.Fatal("SetReadDeadline did not wake the blocked reader")
		}

		// Clearing the deadline restores normal operation.
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		c.pushData([]byte("z"))
		b := make([]byte, 4)
		if n, err := c.Read(b); err != nil || n != 1 || b[0] != 'z' {
			t.Fatalf("Read after clearing deadline = (%d, %v, %q)", n, err, b[:n])
		}
	})

	t.Run("SetDeadline sets both deadlines", func(t *testing.T) {
		c := newPipeConn()
		when := time.Now().Add(time.Hour)
		if err := c.SetDeadline(when); err != nil {
			t.Fatal(err)
		}
		if !c.readDeadline.Equal(when) || !c.writeDeadline.Equal(when) {
			t.Fatalf("deadlines = (%v, %v), want %v", c.readDeadline, c.writeDeadline, when)
		}
	})
}

func TestPipeConnWriteAndClose(t *testing.T) {
	c := newPipeConn()

	var got []byte
	c.writeFunc = func(b []byte) error {
		got = append([]byte(nil), b...)
		return nil
	}
	if n, err := c.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("Write = (%d, %v), want (5, nil)", n, err)
	}
	if string(got) != "hello" {
		t.Errorf("writeFunc received %q, want %q", got, "hello")
	}

	sentinel := errors.New("write failed")
	c.writeFunc = func([]byte) error { return sentinel }
	if _, err := c.Write([]byte("x")); !errors.Is(err, sentinel) {
		t.Errorf("writeFunc error not propagated: %v", err)
	}

	c.writeFunc = nil
	if _, err := c.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Errorf("Write with nil writeFunc = %v, want io.ErrClosedPipe", err)
	}

	c.writeFunc = func(b []byte) error { return nil }
	closeCalls := 0
	c.onClose = func() { closeCalls++ }
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if closeCalls != 1 {
		t.Errorf("onClose called %d times, want 1", closeCalls)
	}
	if n, err := c.Read(make([]byte, 4)); n != 0 || err != io.EOF {
		t.Errorf("Read after Close = (%d, %v), want (0, EOF)", n, err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after Close = %v, want net.ErrClosed", err)
	}

	c.local = ipAddr{ip: testServerIP, port: 80, net: "tcp4"}
	c.remote = ipAddr{ip: testClientIP, port: 12345, net: "tcp4"}
	if c.LocalAddr().Network() != "tcp4" || c.LocalAddr().String() != "192.0.2.2:80" {
		t.Errorf("LocalAddr = %s/%s", c.LocalAddr().Network(), c.LocalAddr())
	}
	if c.RemoteAddr().String() != "192.0.2.1:12345" {
		t.Errorf("RemoteAddr = %s", c.RemoteAddr())
	}
	if _, ok := c.local.(net.Error); ok {
		t.Error("ipAddr must not implement net.Error")
	}
}

// ---------------------------------------------------------------------------
// 9. Stack.Close
// ---------------------------------------------------------------------------

func TestStackClose(t *testing.T) {
	s := New(Config{}, nil)
	if err := s.writePacket([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("writePacket without device = %v, want net.ErrClosed", err)
	}

	dev := newCaptureDevice()
	s.mu.Lock()
	s.device = dev
	s.mu.Unlock()

	if err := s.writePacket(buildIPv4(protoICMP, testClientIP, testServerIP, []byte{1, 2}, 1)); err != nil {
		t.Fatalf("writePacket before Close: %v", err)
	}
	dev.nextWritten(t)

	s.Close()
	if err := s.writePacket([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("writePacket after Close = %v, want net.ErrClosed", err)
	}
	if err := s.SendUDP(testServerIP, 1, testClientIP, 2, nil, false); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SendUDP after Close = %v, want net.ErrClosed", err)
	}
	if !s.isClosed() {
		t.Error("isClosed = false after Close")
	}
	// Repeated Close must not panic or block.
	s.Close()
	s.Close()
}

func TestStackCloseTerminatesConnections(t *testing.T) {
	h := newTestHandler(false)
	s, dev := newStartedStack(t, Config{}, h)
	const clientISN = uint32(77)

	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 5555, 8080, clientISN, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 5555, 8080, clientISN+1, sa.seq+1, flagACK, nil))
	call := h.nextTCP(t)

	s.Close()

	select {
	case <-call.ctx.Done():
	case <-time.After(testTimeout):
		t.Fatal("NewTCP context was not cancelled by Stack.Close")
	}
	b := make([]byte, 4)
	if n, err := call.conn.Read(b); n != 0 || err != io.EOF {
		t.Fatalf("conn.Read after Stack.Close = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestStartNilDevice(t *testing.T) {
	s := New(Config{}, nil)
	done := make(chan struct{})
	go func() {
		s.Start(nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("Start(nil) did not return")
	}
}
