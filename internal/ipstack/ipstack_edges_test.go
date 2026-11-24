package ipstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// failingDevice lets us verify that write errors from the TUN device are
// propagated through writePacket/emitTCP/SendUDP instead of being swallowed.
type failingDevice struct {
	err error
}

func (d *failingDevice) Write([]byte) (int, error) { return 0, d.err }
func (d *failingDevice) Read([]byte) (int, error)  { return 0, io.EOF }

func TestWritePacketPropagatesDeviceError(t *testing.T) {
	sentinel := errors.New("tun write failed")
	s := New(Config{}, nil)
	s.mu.Lock()
	s.device = &failingDevice{err: sentinel}
	s.mu.Unlock()

	pkt := buildIPv4(protoICMP, testClientIP, testServerIP, []byte{1, 2}, 1)
	if err := s.writePacket(pkt); !errors.Is(err, sentinel) {
		t.Errorf("writePacket = %v, want %v", err, sentinel)
	}
	key := tcpKey{srcIP: testClientIP, srcPort: 1234, dstIP: testServerIP, dstPort: 80}
	if err := s.emitTCP(key, 1, 2, flagACK, nil); !errors.Is(err, sentinel) {
		t.Errorf("emitTCP = %v, want %v", err, sentinel)
	}
	if err := s.SendUDP(testServerIP, 1, testClientIP, 2, []byte("x"), true); !errors.Is(err, sentinel) {
		t.Errorf("SendUDP = %v, want %v", err, sentinel)
	}
	// handleICMP deliberately ignores write failures; it must at least not panic.
	s.handleICMP(testClientIP, testServerIP, []byte{8, 0, 0, 0, 0, 0, 0, 0})
}

func TestHandleTCPResetAndUnknownConnection(t *testing.T) {
	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{}, h)
	const isn = uint32(9000)

	// Unsolicited ACK carrying data for an unknown connection is dropped.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 111, 80, isn, 0, flagACK, []byte("orphan")))
	dev.expectQuiet(t, 50*time.Millisecond)

	// SYN -> SYN-ACK.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 111, 80, isn, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if sa.flags != flagSYN|flagACK || sa.ack != isn+1 {
		t.Fatalf("first SYN-ACK = seq %d ack %d flags 0x%02x", sa.seq, sa.ack, sa.flags)
	}

	// RST before the handshake removes the half-open connection.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 111, 80, isn+1, sa.seq+1, flagRST|flagACK, nil))
	dev.expectQuiet(t, 50*time.Millisecond)

	// The same 4-tuple can be reused immediately by a new SYN.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 111, 80, isn+100, 0, flagSYN, nil))
	sa2 := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if sa2.ack != isn+101 {
		t.Errorf("second SYN-ACK ack = %d, want %d", sa2.ack, isn+101)
	}
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 111, 80, isn+101, sa2.seq+1, flagACK, nil))
	call := h.nextTCP(t)

	// Data on a different (unknown) 4-tuple must not reach the handler.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 222, 80, 1, 0, flagPSH|flagACK, []byte("nope")))
	dev.expectQuiet(t, 50*time.Millisecond)

	// RST on the established connection cancels its context and drops it.
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 111, 80, isn+101, sa2.seq+1, flagRST|flagACK, nil))
	select {
	case <-call.ctx.Done():
	case <-time.After(testTimeout):
		t.Fatal("RST did not cancel the established connection")
	}
	dev.expectQuiet(t, 50*time.Millisecond)
}

func TestHandleUDPEdgeCases(t *testing.T) {
	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{}, h)

	// A UDP length shorter than the fixed header is rejected.
	bad := buildIPv4(protoUDP, testClientIP, testServerIP, make([]byte, udpHeaderLen), 1)
	binary.BigEndian.PutUint16(bad[ipHeaderLen+4:ipHeaderLen+6], udpHeaderLen-1)
	dev.feed(t, bad)

	// A length larger than the captured bytes is clamped to the capture.
	long := buildIPv4(protoUDP, testClientIP, testServerIP, make([]byte, udpHeaderLen+3), 2)
	binary.BigEndian.PutUint16(long[ipHeaderLen+4:ipHeaderLen+6], 1000)
	copy(long[ipHeaderLen+udpHeaderLen:], "abc")
	dev.feed(t, long)

	call := h.nextUDP(t)
	if string(call.payload) != "abc" {
		t.Errorf("clamped UDP payload = %q, want %q", call.payload, "abc")
	}
	if call.srcIP != testClientIP || call.dstIP != testServerIP {
		t.Errorf("UDP addresses = %v -> %v", call.srcIP, call.dstIP)
	}
	h.expectNoUDP(t, 50*time.Millisecond)

	// A nil handler is allowed: no callbacks, no panic, no output.
	_, dev2 := newStartedStack(t, Config{}, nil)
	dev2.feed(t, buildUDPPacket(testClientIP, testServerIP, 1, 2, []byte("ignored")))
	dev2.expectQuiet(t, 50*time.Millisecond)
}

func TestTCPMTUFallback(t *testing.T) {
	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{MTU: 20}, h) // <= 40: fall back to 1400

	const isn = uint32(300)
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 1234, 80, isn, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 1234, 80, isn+1, sa.seq+1, flagACK, nil))
	call := h.nextTCP(t)

	data := bytes.Repeat([]byte("z"), 1500)
	if n, err := call.conn.Write(data); err != nil || n != len(data) {
		t.Fatalf("conn.Write = (%d, %v)", n, err)
	}
	packets := dev.waitWritten(t, 2, testTimeout)
	var lengths []int
	var reassembled []byte
	for _, pkt := range packets {
		seg := parseTCPOrFail(t, parseIPv4OrFail(t, pkt))
		lengths = append(lengths, len(seg.payload))
		reassembled = append(reassembled, seg.payload...)
	}
	if len(lengths) != 2 || lengths[0] != 1400 || lengths[1] != 100 {
		t.Errorf("segment lengths = %v, want [1400 100]", lengths)
	}
	if !bytes.Equal(reassembled, data) {
		t.Error("reassembled fallback data does not match the input")
	}
}

func TestSendTCPDataOnClosedState(t *testing.T) {
	h := newTestHandler(false)
	s, dev := newStartedStack(t, Config{}, h)
	const isn = uint32(6000)
	const srcPort = uint16(4321)

	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, srcPort, 80, isn, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, srcPort, 80, isn+1, sa.seq+1, flagACK, nil))
	h.nextTCP(t)

	key := tcpKey{srcIP: testClientIP, srcPort: srcPort, dstIP: testServerIP, dstPort: 80}
	s.mu.Lock()
	tc := s.conns[key]
	s.mu.Unlock()
	if tc == nil {
		t.Fatal("connection not found in stack map")
	}
	tc.mu.Lock()
	tc.state = tcpClosed
	tc.mu.Unlock()

	if err := s.sendTCPData(tc, []byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("sendTCPData on closed conn = %v, want net.ErrClosed", err)
	}
	dev.expectQuiet(t, 50*time.Millisecond)
}

func TestNilHandlerHandshakeAndData(t *testing.T) {
	_, dev := newStartedStack(t, Config{}, nil)
	const isn = uint32(7000)

	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 123, 80, isn, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 123, 80, isn+1, sa.seq+1, flagACK, nil))

	// No NewTCP callback, but inbound data is still buffered and ACKed.
	payload := []byte("no handler")
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 123, 80, isn+1, sa.seq+1, flagPSH|flagACK, payload))
	ack := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if ack.flags != flagACK || ack.ack != isn+1+uint32(len(payload)) {
		t.Errorf("ACK = flags 0x%02x ack %d", ack.flags, ack.ack)
	}

	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, 123, 80, isn+1+uint32(len(payload)), sa.seq+1, flagFIN|flagACK, nil))
	fin := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	if fin.flags != flagFIN|flagACK {
		t.Errorf("FIN response flags = 0x%02x", fin.flags)
	}
	dev.expectQuiet(t, 50*time.Millisecond)
}

func TestSendUDPZeroChecksumEncoding(t *testing.T) {
	s, dev := newStartedStack(t, Config{}, nil)
	src, dst := testServerIP, testClientIP
	const srcPort, dstPort uint16 = 1111, 2222

	// Find a two-byte payload whose UDP checksum works out to zero. Varying a
	// single 16-bit word is a bijection over the 16-bit checksum, so a solution
	// is guaranteed to exist.
	var payload []byte
	found := false
	for v := 0; v < 0x10000 && !found; v++ {
		candidate := []byte{byte(v >> 8), byte(v)}
		seg := make([]byte, udpHeaderLen+len(candidate))
		binary.BigEndian.PutUint16(seg[0:2], srcPort)
		binary.BigEndian.PutUint16(seg[2:4], dstPort)
		binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
		copy(seg[udpHeaderLen:], candidate)
		if udpChecksum(src, dst, seg) == 0 {
			payload = candidate
			found = true
		}
	}
	if !found {
		t.Fatal("no two-byte payload produced a zero UDP checksum")
	}
	if err := s.SendUDP(src, srcPort, dst, dstPort, payload, true); err != nil {
		t.Fatal(err)
	}
	ip := parseIPv4OrFail(t, dev.nextWritten(t))
	if got := binary.BigEndian.Uint16(ip.payload[6:8]); got != 0xffff {
		t.Fatalf("emitted zero checksum = 0x%04x, want 0xffff", got)
	}
	verifyTransportChecksum(t, src, dst, protoUDP, ip.payload)
}

func TestSendTCPDataPropagatesWriteError(t *testing.T) {
	h := newTestHandler(false)
	_, dev := newStartedStack(t, Config{}, h)
	const isn = uint32(8000)
	const srcPort = uint16(5151)

	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, srcPort, 80, isn, 0, flagSYN, nil))
	sa := parseTCPOrFail(t, parseIPv4OrFail(t, dev.nextWritten(t)))
	dev.feed(t, buildTCPPacket(testClientIP, testServerIP, srcPort, 80, isn+1, sa.seq+1, flagACK, nil))
	call := h.nextTCP(t)

	sentinel := errors.New("device gone")
	dev.setWriteErr(sentinel)

	if _, err := call.conn.Write([]byte("x")); !errors.Is(err, sentinel) {
		t.Errorf("conn.Write = %v, want %v", err, sentinel)
	}
}

func TestPipeConnDataWakesReaderWithFutureDeadline(t *testing.T) {
	c := newPipeConn()
	if err := c.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	res := make(chan readResult, 1)
	go func() {
		b := make([]byte, 8)
		n, err := c.Read(b)
		res <- readResult{n: n, err: err, data: append([]byte(nil), b[:n]...)}
	}()
	select {
	case r := <-res:
		t.Fatalf("Read returned before data: %+v", r)
	case <-time.After(30 * time.Millisecond):
	}
	c.pushData([]byte("ok"))
	select {
	case r := <-res:
		if r.err != nil || string(r.data) != "ok" {
			t.Fatalf("Read = (%d, %v, %q), want (2, nil, \"ok\")", r.n, r.err, r.data)
		}
	case <-time.After(testTimeout):
		t.Fatal("data did not wake the reader with a future deadline")
	}
}

func TestPipeConnDeadlineExactlyNow(t *testing.T) {
	c := newPipeConn()
	// A deadline equal to "now" exercises the expired-deadline branch before
	// the timer is allocated.
	if err := c.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 4))
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("Read with now-deadline returned %v, want a timeout", err)
	}
}

// packetAndErrorDevice returns one packet together with a read error, which is
// what a TUN device does when the final read races with device teardown.
type packetAndErrorDevice struct {
	pkt     []byte
	err     error
	served  bool
	written [][]byte
}

func (d *packetAndErrorDevice) Read(p []byte) (int, error) {
	if d.served {
		return 0, io.EOF
	}
	d.served = true
	return copy(p, d.pkt), d.err
}

func (d *packetAndErrorDevice) Write(p []byte) (int, error) {
	d.written = append(d.written, append([]byte(nil), p...))
	return len(p), nil
}

func TestStartHandlesPacketReturnedWithReadError(t *testing.T) {
	dev := &packetAndErrorDevice{
		pkt: buildICMPEchoRequest(9, 10, []byte("x")),
		err: errors.New("read failed"),
	}
	s := New(Config{}, nil)
	s.Start(dev) // returns after the first read

	if len(dev.written) != 1 {
		t.Fatalf("device received %d packets, want 1", len(dev.written))
	}
	ip, ok := parseIPv4(dev.written[0])
	if !ok || ip.proto != protoICMP || len(ip.payload) < 8 || ip.payload[0] != 0 {
		t.Fatalf("expected an ICMP Echo Reply, got %+v", ip)
	}
}

func TestTimeoutErrorDetails(t *testing.T) {
	var err error = timeoutError{}
	if got := err.Error(); got != "i/o timeout" {
		t.Errorf("Error() = %q, want %q", got, "i/o timeout")
	}
	ne, ok := err.(net.Error)
	if !ok {
		t.Fatal("timeoutError does not implement net.Error")
	}
	if !ne.Timeout() || !ne.Temporary() {
		t.Error("timeoutError must report Timeout() and Temporary() as true")
	}
}
