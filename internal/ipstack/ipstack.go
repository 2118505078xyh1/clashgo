// Package ipstack implements a minimal, dependency-free IPv4 userspace stack
// for TUN devices.
//
// A TUN device is modelled as an io.ReadWriter that carries complete IPv4
// packets: reads return one raw IP packet and writes expect one raw IP packet.
// The stack terminates TCP connections (performing a fake three-way handshake
// on behalf of the destination) and hands them to a Handler as net.Conn
// values. UDP datagrams are dispatched directly to the Handler. ICMP echo
// requests are answered so that "ping <gateway>" works.
//
// Only the Go standard library is used.
package ipstack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10

	ipHeaderLen  = 20
	tcpHeaderLen = 20
	udpHeaderLen = 8
)

// Config configures a Stack.
//
// Gateway is recorded for reference (the stack itself simply swaps the source
// and destination addresses when replying, which makes any destination
// address reachable). MTU is used to bound the size of emitted TCP segments;
// a value <= 0 falls back to 1500.
type Config struct {
	Gateway [4]byte
	MTU     int
}

// Handler receives the streams and datagrams assembled by the stack.
//
// NewTCP is called once the three-way handshake has been completed. The
// supplied conn carries the TCP byte stream: data read from the TUN device for
// this connection can be obtained with conn.Read, and anything written with
// conn.Write is emitted as TCP data segments back to the TUN device.
type Handler interface {
	NewTCP(ctx context.Context, srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, conn net.Conn)
	NewUDP(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, payload []byte)
}

// Stack is a userspace IPv4 stack attached to a TUN device.
type Stack struct {
	cfg     Config
	handler Handler

	mu     sync.Mutex
	device io.ReadWriter
	closed bool
	conns  map[tcpKey]*tcpConn

	writeMu   sync.Mutex // serializes writes to the device
	closeOnce sync.Once

	ipID uint32
}

// New creates a Stack. h may be nil, in which case no callbacks are made.
func New(cfg Config, h Handler) *Stack {
	if cfg.MTU <= 0 {
		cfg.MTU = 1500
	}
	s := &Stack{
		cfg:     cfg,
		handler: h,
		conns:   make(map[tcpKey]*tcpConn),
		ipID:    randomUint32(),
	}
	return s
}

// Start runs the packet receive loop on device. It blocks until the device
// returns an error (including the one caused by Close) or until Close is
// called. Only one Start call should be active at a time.
func (s *Stack) Start(device io.ReadWriter) {
	if device == nil {
		return
	}
	s.mu.Lock()
	s.device = device
	s.mu.Unlock()

	buf := make([]byte, 65535)
	for {
		n, err := device.Read(buf)
		if n > 0 {
			s.handlePacket(buf[:n])
		}
		if err != nil {
			if s.isClosed() {
				return
			}
			// A permanent read error ends the loop. Callers can restart the
			// stack on a fresh device if desired.
			return
		}
	}
}

// Close shuts the stack down: it rejects further writes, terminates all
// virtual TCP connections and closes the device when it implements io.Closer
// (this also unblocks a running Start). Close is safe to call repeatedly.
func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		dev := s.device
		conns := make([]*tcpConn, 0, len(s.conns))
		for _, tc := range s.conns {
			conns = append(conns, tc)
		}
		s.conns = make(map[tcpKey]*tcpConn)
		s.mu.Unlock()

		for _, tc := range conns {
			tc.cancel()
			tc.pipe.shutdown()
		}
		if dev != nil {
			if c, ok := dev.(io.Closer); ok {
				_ = c.Close()
			}
		}
	})
}

func (s *Stack) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// SendUDP emits a UDP datagram as a complete IPv4 packet. Upper layers can use
// this to answer datagrams delivered to Handler.NewUDP. A zero checksum is
// emitted when checksum==false; otherwise a full pseudo-header checksum is
// computed.
func (s *Stack) SendUDP(srcIP [4]byte, srcPort uint16, dstIP [4]byte, dstPort uint16, payload []byte, checksum bool) error {
	seg := make([]byte, udpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	binary.BigEndian.PutUint16(seg[4:6], uint16(len(seg)))
	// seg[6:8] (checksum) is zero for now.
	copy(seg[udpHeaderLen:], payload)
	if checksum {
		c := udpChecksum(srcIP, dstIP, seg)
		if c == 0 {
			c = 0xffff // zero means "no checksum" in UDPv4
		}
		binary.BigEndian.PutUint16(seg[6:8], c)
	}
	return s.writePacket(buildIPv4(protoUDP, srcIP, dstIP, seg, s.nextIPID()))
}

// ---------------------------------------------------------------------------
// Packet dispatch / IPv4
// ---------------------------------------------------------------------------

type ipv4Packet struct {
	version   int
	ihl       int
	tos       uint8
	totalLen  int
	id        uint16
	flagsFrag uint16
	ttl       uint8
	proto     uint8
	src       [4]byte
	dst       [4]byte
	payload   []byte
}

func parseIPv4(pkt []byte) (ipv4Packet, bool) {
	var out ipv4Packet
	if len(pkt) < ipHeaderLen {
		return out, false
	}
	vihl := pkt[0]
	if vihl>>4 != 4 {
		return out, false
	}
	ihl := int(vihl&0x0f) * 4
	if ihl < ipHeaderLen || ihl > len(pkt) {
		return out, false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl || total > len(pkt) {
		total = len(pkt) // tolerate slightly inconsistent lengths
	}
	out.version = 4
	out.ihl = ihl
	out.tos = pkt[1]
	out.totalLen = total
	out.id = binary.BigEndian.Uint16(pkt[4:6])
	out.flagsFrag = binary.BigEndian.Uint16(pkt[6:8])
	out.ttl = pkt[8]
	out.proto = pkt[9]
	copy(out.src[:], pkt[12:16])
	copy(out.dst[:], pkt[16:20])
	out.payload = pkt[ihl:total]
	return out, true
}

func buildIPv4(proto uint8, src, dst [4]byte, payload []byte, id uint16) []byte {
	pkt := make([]byte, ipHeaderLen+len(payload))
	pkt[0] = 0x45 // IPv4, 5-word header
	pkt[1] = 0    // TOS
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // Don't Fragment
	pkt[8] = 64                                  // TTL
	pkt[9] = proto
	// checksum field at pkt[10:12] stays zero while computing
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[ipHeaderLen:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ipHeaderLen]))
	return pkt
}

func (s *Stack) handlePacket(pkt []byte) {
	ip, ok := parseIPv4(pkt)
	if !ok {
		return
	}
	// Non-first fragments cannot be parsed as TCP/UDP; drop them.
	if ip.flagsFrag&0x1fff != 0 {
		return
	}
	switch ip.proto {
	case protoTCP:
		s.handleTCP(ip.src, ip.dst, ip.payload)
	case protoUDP:
		s.handleUDP(ip.src, ip.dst, ip.payload)
	case protoICMP:
		s.handleICMP(ip.src, ip.dst, ip.payload)
	}
}

func (s *Stack) writePacket(pkt []byte) error {
	s.mu.Lock()
	if s.closed || s.device == nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	dev := s.device
	s.mu.Unlock()

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := dev.Write(pkt)
	return err
}

func (s *Stack) nextIPID() uint16 {
	return uint16(atomic.AddUint32(&s.ipID, 1))
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

// checksum computes the standard Internet checksum: the ones' complement of
// the ones'-complement sum of all 16-bit words in data (padded with a zero
// byte when odd).
func checksum(data []byte) uint16 {
	var sum uint32
	i := 0
	for i+1 < len(data) {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
		i += 2
	}
	if i < len(data) {
		sum += uint32(data[i]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst [4]byte, seg []byte) uint16 {
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	// seg[16:18] is the checksum field and must be zero here.
	return checksum(pseudo)
}

func udpChecksum(src, dst [4]byte, seg []byte) uint16 {
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = protoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	// seg[6:8] is the checksum field and must be zero here.
	return checksum(pseudo)
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

type tcpKey struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
}

type tcpState uint8

const (
	tcpSynReceived tcpState = iota + 1
	tcpEstablished
	tcpClosed
)

// tcpConn holds the per-connection sequence numbers and state. The key is
// always expressed from the client's point of view (src = client).
type tcpConn struct {
	stack *Stack
	key   tcpKey
	pipe  *pipeConn

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex // protects state and sequence numbers
	state  tcpState
	sndNxt uint32 // next sequence number we send
	rcvNxt uint32 // next sequence number we expect to receive

	writeMu sync.Mutex // serializes emitted segments
}

func (s *Stack) handleTCP(srcIP, dstIP [4]byte, seg []byte) {
	if len(seg) < tcpHeaderLen {
		return
	}
	srcPort := binary.BigEndian.Uint16(seg[0:2])
	dstPort := binary.BigEndian.Uint16(seg[2:4])
	seq := binary.BigEndian.Uint32(seg[4:8])
	dataOff := int((seg[12] >> 4) * 4)
	if dataOff < tcpHeaderLen || dataOff > len(seg) {
		return
	}
	flags := seg[13]
	data := seg[dataOff:]

	key := tcpKey{srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}

	s.mu.Lock()
	tc := s.conns[key]
	s.mu.Unlock()

	// SYN without ACK: create the connection and answer with SYN-ACK.
	if flags&flagSYN != 0 && flags&flagACK == 0 {
		if tc == nil {
			s.newTCPConn(key, seq)
		} else {
			// Retransmitted SYN: resend SYN-ACK.
			_ = s.emitTCP(key, tc.nextSendSeq(), tc.currentRecvSeq(), flagSYN|flagACK, nil)
		}
		return
	}

	if tc == nil {
		// Unsolicited data/ACK for an unknown connection: ignore it.
		return
	}

	if flags&flagRST != 0 {
		s.dropTCPConn(tc)
		return
	}

	// ACK completing the three-way handshake.
	if tc.getState() == tcpSynReceived && flags&flagACK != 0 {
		tc.mu.Lock()
		tc.state = tcpEstablished
		tc.sndNxt++ // our SYN is now acknowledged
		tc.rcvNxt = seq
		tc.mu.Unlock()
		if s.handler != nil {
			go s.handler.NewTCP(tc.ctx, key.srcIP, key.srcPort, key.dstIP, key.dstPort, tc.pipe)
		}
		// An ACK may carry data; deliver it below.
	}

	if len(data) > 0 {
		// 必须先推进 rcvNxt 再唤醒上层：否则上层 Write 触发 sendTCPData
		// 时读到的 ACK 号会落后一个 payload 长度（竞态）。
		tc.mu.Lock()
		tc.rcvNxt += uint32(len(data))
		rcv := tc.rcvNxt
		tc.mu.Unlock()
		_ = s.emitTCP(key, tc.nextSendSeq(), rcv, flagACK, nil)
		tc.pipe.pushData(data)
	}

	if flags&flagFIN != 0 {
		// FIN consumes one sequence number at the receiver.
		tc.mu.Lock()
		tc.rcvNxt++
		rcv := tc.rcvNxt
		snd := tc.sndNxt
		tc.sndNxt++ // our FIN consumes one sequence number too
		tc.state = tcpClosed
		tc.mu.Unlock()
		_ = s.emitTCP(key, snd, rcv, flagFIN|flagACK, nil)
		s.dropTCPConn(tc)
	}
}

func (s *Stack) newTCPConn(key tcpKey, clientISN uint32) *tcpConn {
	ctx, cancel := context.WithCancel(context.Background())
	tc := &tcpConn{
		stack:  s,
		key:    key,
		ctx:    ctx,
		cancel: cancel,
		state:  tcpSynReceived,
		sndNxt: randomUint32(),
		rcvNxt: clientISN + 1,
	}
	pipe := newPipeConn()
	pipe.local = ipAddr{ip: key.dstIP, port: key.dstPort, net: "tcp4"}
	pipe.remote = ipAddr{ip: key.srcIP, port: key.srcPort, net: "tcp4"}
	pipe.onClose = func() {
		// Upper layer closed the conn: send FIN and forget the connection.
		tc.mu.Lock()
		if tc.state == tcpClosed {
			tc.mu.Unlock()
			return
		}
		snd, rcv := tc.sndNxt, tc.rcvNxt
		tc.sndNxt++
		tc.state = tcpClosed
		tc.mu.Unlock()
		_ = s.emitTCP(key, snd, rcv, flagFIN|flagACK, nil)
		s.dropTCPConn(tc)
		cancel()
	}
	pipe.writeFunc = func(b []byte) error { return s.sendTCPData(tc, b) }
	tc.pipe = pipe

	s.mu.Lock()
	s.conns[key] = tc
	s.mu.Unlock()

	// Send SYN-ACK: seq = our ISN, ack = client ISN + 1.
	_ = s.emitTCP(key, tc.sndNxt, tc.rcvNxt, flagSYN|flagACK, nil)
	return tc
}

func (s *Stack) dropTCPConn(tc *tcpConn) {
	s.mu.Lock()
	if s.conns[tc.key] == tc {
		delete(s.conns, tc.key)
	}
	s.mu.Unlock()
	tc.cancel()
	tc.pipe.shutdown()
}

func (s *Stack) sendTCPData(tc *tcpConn, data []byte) error {
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()
	max := s.cfg.MTU - ipHeaderLen - tcpHeaderLen
	if max <= 0 {
		max = 1400
	}
	for len(data) > 0 {
		n := len(data)
		if n > max {
			n = max
		}
		chunk := data[:n]
		data = data[n:]

		tc.mu.Lock()
		if tc.state == tcpClosed {
			tc.mu.Unlock()
			return net.ErrClosed
		}
		seq, ack := tc.sndNxt, tc.rcvNxt
		tc.sndNxt += uint32(n)
		tc.mu.Unlock()

		if err := s.emitTCP(tc.key, seq, ack, flagPSH|flagACK, chunk); err != nil {
			return err
		}
	}
	return nil
}

// emitTCP builds one TCP segment. The key is in client orientation, so the
// reply swaps source and destination.
func (s *Stack) emitTCP(key tcpKey, seq, ack uint32, flags uint8, payload []byte) error {
	seg := make([]byte, tcpHeaderLen+len(payload))
	binary.BigEndian.PutUint16(seg[0:2], key.dstPort) // our port = client's dst
	binary.BigEndian.PutUint16(seg[2:4], key.srcPort)
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], ack)
	seg[12] = 5 << 4 // data offset = 5 words
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535) // advertised window
	// checksum at seg[16:18] is zero while computing
	copy(seg[tcpHeaderLen:], payload)
	binary.BigEndian.PutUint16(seg[16:18], tcpChecksum(key.dstIP, key.srcIP, seg))
	return s.writePacket(buildIPv4(protoTCP, key.dstIP, key.srcIP, seg, s.nextIPID()))
}

func (tc *tcpConn) getState() tcpState {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.state
}

func (tc *tcpConn) nextSendSeq() uint32 {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.sndNxt
}

func (tc *tcpConn) currentRecvSeq() uint32 {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.rcvNxt
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

func (s *Stack) handleUDP(srcIP, dstIP [4]byte, seg []byte) {
	if len(seg) < udpHeaderLen {
		return
	}
	srcPort := binary.BigEndian.Uint16(seg[0:2])
	dstPort := binary.BigEndian.Uint16(seg[2:4])
	length := int(binary.BigEndian.Uint16(seg[4:6]))
	if length < udpHeaderLen {
		return
	}
	if length > len(seg) {
		length = len(seg)
	}
	payload := append([]byte(nil), seg[udpHeaderLen:length]...)
	if s.handler != nil {
		s.handler.NewUDP(srcIP, srcPort, dstIP, dstPort, payload)
	}
}

// ---------------------------------------------------------------------------
// ICMP
// ---------------------------------------------------------------------------

func (s *Stack) handleICMP(srcIP, dstIP [4]byte, msg []byte) {
	if len(msg) < 8 {
		return
	}
	if msg[0] != 8 || msg[1] != 0 { // Echo Request
		return
	}
	reply := append([]byte(nil), msg...)
	reply[0] = 0 // Echo Reply
	reply[1] = 0
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], checksum(reply))
	_ = s.writePacket(buildIPv4(protoICMP, dstIP, srcIP, reply, s.nextIPID()))
}

// ---------------------------------------------------------------------------
// Virtual net.Conn
// ---------------------------------------------------------------------------

type pipeConn struct {
	mu      sync.Mutex
	readBuf []byte
	notify  chan struct{} // buffered(1) "data available / closed" signal
	closed  bool

	readDeadline  time.Time
	writeDeadline time.Time

	writeFunc func([]byte) error
	onClose   func()
	closeOnce sync.Once

	local, remote net.Addr
}

func newPipeConn() *pipeConn {
	return &pipeConn{notify: make(chan struct{}, 1)}
}

func (c *pipeConn) signal() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *pipeConn) pushData(b []byte) {
	c.mu.Lock()
	c.readBuf = append(c.readBuf, b...)
	c.mu.Unlock()
	c.signal()
}

func (c *pipeConn) shutdown() {
	c.mu.Lock()
	already := c.closed
	c.closed = true
	c.mu.Unlock()
	if !already {
		c.signal()
	}
}

func (c *pipeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		deadline := c.readDeadline
		c.mu.Unlock()

		if deadline.IsZero() {
			<-c.notify
			continue
		}
		d := time.Until(deadline)
		if d <= 0 {
			return 0, timeoutError{}
		}
		timer := time.NewTimer(d)
		select {
		case <-c.notify:
			timer.Stop()
		case <-timer.C:
			return 0, timeoutError{}
		}
	}
}

func (c *pipeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	wf := c.writeFunc
	deadline := c.writeDeadline
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if wf == nil {
		return 0, io.ErrClosedPipe
	}
	if deadline.IsZero() {
		if err := wf(b); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	// 尊重 SetWriteDeadline：在独立 goroutine 中执行实际写入，
	// 超时则立即返回 timeoutError（与 net.Conn 语义一致）。
	done := make(chan error, 1)
	go func() { done <- wf(b) }()
	d := time.Until(deadline)
	if d <= 0 {
		return 0, timeoutError{}
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return 0, err
		}
		return len(b), nil
	case <-timer.C:
		return 0, timeoutError{}
	}
}

func (c *pipeConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		c.shutdown()
	})
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return c.local }
func (c *pipeConn) RemoteAddr() net.Addr { return c.remote }

func (c *pipeConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	c.signal() // wake a blocked reader so it can re-evaluate the deadline
	return nil
}

func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

type ipAddr struct {
	ip   [4]byte
	port uint16
	net  string
}

func (a ipAddr) Network() string { return a.net }
func (a ipAddr) String() string {
	return net.JoinHostPort(net.IP(a.ip[:]).String(), strconv.Itoa(int(a.port)))
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

var _ net.Error = timeoutError{}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint32(b[:])
	}
	return uint32(time.Now().UnixNano())
}
