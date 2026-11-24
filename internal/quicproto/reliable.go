package quicproto

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// 最小可靠 UDP 层（"QUIC-like" 传输）。
//
// 这不是 QUIC：没有 TLS 1.3、没有真正的拥塞控制、没有多流复用、没有连接迁移。
// 它只是一个带序列号 / 累积 ACK / 超时重传 / 滑动窗口的停止-等待改进版 ARQ，
// 用来在纯标准库条件下承载 Hysteria2 / TUIC 的协议头与加密记录层。
//
// 线格式（所有多字节整数均为 big endian）：
//
//	 0                   1                   2                   3
//	| magic = 0x5152    | version = 1       | flags             |  <- 4
//	| seq (4)                                                    |  <- 8
//	| ack (4)  = 对端期望收到的下一个 seq（小于它的都已确认）      |  <- 12
//	| length (2)                                                 |  <- 14
//	| payload (length)                                           |
//
// flags: bit0 DATA, bit1 ACK, bit2 SYN, bit3 FIN。
// SYN / FIN 各消耗一个序列号；DATA 每个包消耗一个序列号。
const (
	packetMagic     uint16 = 0x5152 // "QR"
	packetVersion   byte   = 1
	packetHeaderLen        = 14
	maxPayload             = 1200 // 单包最大载荷，保证 UDP 数据报 < 1280
	maxDatagram            = 2048

	flagData byte = 0x01
	flagACK  byte = 0x02
	flagSYN  byte = 0x04
	flagFIN  byte = 0x08

	windowSize = 16 // 发送滑动窗口（未确认包上限）
	maxRetries = 12 // 单包最大重传次数
	initialRTO = 250 * time.Millisecond
	minRTO     = 50 * time.Millisecond
	maxRTO     = 2 * time.Second
	tickEvery  = 20 * time.Millisecond

	handshakeTimeout = 5 * time.Second
)

// timeoutError 实现 net.Error，语义与 net.OpError 的超时一致。
type timeoutError struct{ op string }

func (e *timeoutError) Error() string   { return "quicproto: " + e.op + " i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// packet 是解析后的 UDP 数据报。
type packet struct {
	flags   byte
	seq     uint32
	ack     uint32
	payload []byte
}

func parsePacket(b []byte) (packet, error) {
	var p packet
	if len(b) < packetHeaderLen {
		return p, errors.New("quicproto: udp packet too short")
	}
	if binary.BigEndian.Uint16(b[:2]) != packetMagic {
		return p, errors.New("quicproto: bad udp packet magic")
	}
	if b[2] != packetVersion {
		return p, errors.New("quicproto: unsupported udp packet version")
	}
	p.flags = b[3]
	p.seq = binary.BigEndian.Uint32(b[4:8])
	p.ack = binary.BigEndian.Uint32(b[8:12])
	n := int(binary.BigEndian.Uint16(b[12:14]))
	if n > len(b)-packetHeaderLen {
		return p, errors.New("quicproto: udp packet length mismatch")
	}
	p.payload = b[packetHeaderLen : packetHeaderLen+n]
	return p, nil
}

// seqLess 用有符号差值判断 uint32 序列号的前后关系，正确处理回绕。
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func sameAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// pendingPacket 是发送窗口中一个尚未被确认的数据包。
type pendingPacket struct {
	seq   uint32
	data  []byte
	sent  time.Time
	tries int
}

// reliableConn 实现基于 UDP 的最小可靠字节流（net.Conn）。
type reliableConn struct {
	udp    *net.UDPConn
	remote *net.UDPAddr

	// 发送状态，由 writeMu 保护。
	writeMu sync.Mutex
	base    uint32 // 最小未确认序列号
	next    uint32 // 下一个待分配序列号
	window  map[uint32]*pendingPacket
	srtt    time.Duration
	rttvar  time.Duration
	rto     time.Duration
	ackCh   chan struct{}

	// 接收状态，由 readMu 保护。
	readMu     sync.Mutex
	expected   uint32 // 期望收到的下一个序列号
	outOfOrder map[uint32][]byte
	rbuf       []byte
	readErr    error
	dataCh     chan struct{}

	// 期限由 deadlineMu 保护；true 表示读期限，false 表示写期限。
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	fatalMu  sync.Mutex
	fatalErr error

	done chan struct{}
	once sync.Once
}

func newReliableConn(udp *net.UDPConn, remote *net.UDPAddr) *reliableConn {
	return &reliableConn{
		udp:        udp,
		remote:     remote,
		window:     make(map[uint32]*pendingPacket),
		outOfOrder: make(map[uint32][]byte),
		ackCh:      make(chan struct{}, 1),
		dataCh:     make(chan struct{}, 1),
		rto:        initialRTO,
		done:       make(chan struct{}),
	}
}

func (c *reliableConn) start() {
	go c.recvLoop()
	go c.retransmitLoop()
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

// dialReliable 在给定 UDP 地址上完成 SYN / SYN-ACK / ACK 三次握手。
func dialReliable(ctx context.Context, address string) (*reliableConn, error) {
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	closeOnErr := func(err error) (*reliableConn, error) {
		udp.Close()
		return nil, err
	}

	initial, err := randomUint32()
	if err != nil {
		return closeOnErr(err)
	}
	rc := newReliableConn(udp, remote)
	rc.next = initial + 1 // SYN 消耗 initial

	if err := rc.sendPacket(flagSYN, initial, 0, nil); err != nil {
		return closeOnErr(err)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}
	buf := make([]byte, maxDatagram)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return closeOnErr(err)
		}
		_ = udp.SetReadDeadline(deadline)
		n, from, err := udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return closeOnErr(err)
		}
		if !sameAddr(from, remote) {
			continue
		}
		p, err := parsePacket(buf[:n])
		if err != nil || p.flags&flagSYN == 0 || p.flags&flagACK == 0 {
			continue
		}
		if p.ack != initial+1 { // 不是对我们 SYN 的确认
			continue
		}
		rc.expected = p.seq + 1 // 对端的 SYN 消耗一个序列号
		if err := rc.sendPacket(flagACK, rc.next, rc.expected, nil); err != nil {
			return closeOnErr(err)
		}
		_ = udp.SetReadDeadline(time.Time{})
		rc.start()
		return rc, nil
	}
	if err := ctx.Err(); err != nil {
		return closeOnErr(err)
	}
	return closeOnErr(&timeoutError{op: "handshake"})
}

// acceptReliable 在一个已监听的 UDP socket 上接受一个可靠连接。
// 仅供简化版服务端 / 回环测试使用；生产环境应替换为真正的 QUIC 监听。
func acceptReliable(l *net.UDPConn) (*reliableConn, error) {
	buf := make([]byte, maxDatagram)
	deadline := time.Now().Add(handshakeTimeout)

	var remote *net.UDPAddr
	var peerInitial uint32
	for time.Now().Before(deadline) {
		_ = l.SetReadDeadline(deadline)
		n, from, err := l.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, err
		}
		p, err := parsePacket(buf[:n])
		if err != nil || p.flags&flagSYN == 0 || p.flags&flagACK != 0 {
			continue
		}
		remote = from
		peerInitial = p.seq
		break
	}
	if remote == nil {
		return nil, &timeoutError{op: "accept"}
	}

	initial, err := randomUint32()
	if err != nil {
		return nil, err
	}
	rc := newReliableConn(l, remote)
	rc.next = initial + 1
	rc.expected = peerInitial + 1

	if err := rc.sendPacket(flagSYN|flagACK, initial, rc.expected, nil); err != nil {
		return nil, err
	}

	for time.Now().Before(deadline) {
		_ = l.SetReadDeadline(deadline)
		n, from, err := l.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return nil, err
		}
		if !sameAddr(from, remote) {
			continue
		}
		p, err := parsePacket(buf[:n])
		if err != nil || p.flags&flagACK == 0 || p.flags&flagSYN != 0 {
			continue
		}
		if p.ack != rc.next {
			continue
		}
		_ = l.SetReadDeadline(time.Time{})
		rc.start()
		return rc, nil
	}
	return nil, &timeoutError{op: "accept handshake"}
}

// ---------------------------------------------------------------------------
// 发包与收包
// ---------------------------------------------------------------------------

func (c *reliableConn) sendPacket(flags byte, seq, ack uint32, payload []byte) error {
	if len(payload) > maxPayload {
		return errors.New("quicproto: udp payload too large")
	}
	buf := make([]byte, packetHeaderLen+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], packetMagic)
	buf[2] = packetVersion
	buf[3] = flags
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ack)
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(payload)))
	copy(buf[packetHeaderLen:], payload)
	if _, err := c.udp.WriteToUDP(buf, c.remote); err != nil {
		c.setFatal(err)
		signal(c.dataCh)
		return err
	}
	return nil
}

func (c *reliableConn) currentExpected() uint32 {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.expected
}

// processAck 处理累积确认：ack 表示对端期望收到的下一个序列号。
func (c *reliableConn) processAck(ack uint32) {
	c.writeMu.Lock()
	removed := 0
	var rttSample time.Duration
	var sampled bool
	for seq, p := range c.window {
		if seqLess(seq, ack) {
			now := time.Now()
			if p.tries == 1 && !sampled {
				rttSample = now.Sub(p.sent)
				sampled = true
			}
			delete(c.window, seq)
			removed++
		}
	}
	if removed > 0 {
		c.base = ack
		if sampled && rttSample > 0 && rttSample < 5*time.Second {
			c.updateRTT(rttSample)
		}
		signal(c.ackCh)
	}
	c.writeMu.Unlock()
}

func (c *reliableConn) updateRTT(r time.Duration) {
	if c.srtt == 0 {
		c.srtt = r
		c.rttvar = r / 2
	} else {
		d := c.srtt - r
		if d < 0 {
			d = -d
		}
		c.rttvar = (3*c.rttvar + d) / 4
		c.srtt = (7*c.srtt + r) / 8
	}
	rto := c.srtt + 4*c.rttvar
	if rto < minRTO {
		rto = minRTO
	}
	if rto > maxRTO {
		rto = maxRTO
	}
	c.rto = rto
}

func (c *reliableConn) processData(seq uint32, data []byte) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if seq == c.expected {
		c.rbuf = append(c.rbuf, data...)
		c.expected++
		for {
			d, ok := c.outOfOrder[c.expected]
			if !ok {
				break
			}
			c.rbuf = append(c.rbuf, d...)
			delete(c.outOfOrder, c.expected)
			c.expected++
		}
		signal(c.dataCh)
		return
	}
	if seqLess(seq, c.expected) {
		return // 重复包，忽略
	}
	if _, exists := c.outOfOrder[seq]; !exists && len(c.outOfOrder) < windowSize*2 {
		c.outOfOrder[seq] = append([]byte(nil), data...)
	}
}

func (c *reliableConn) recvLoop() {
	buf := make([]byte, maxDatagram)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			c.setFatal(err)
			signal(c.dataCh)
			signal(c.ackCh)
			return
		}
		if !sameAddr(from, c.remote) {
			continue
		}
		p, err := parsePacket(buf[:n])
		if err != nil {
			continue
		}
		c.processAck(p.ack)

		if p.flags&flagFIN != 0 {
			c.readMu.Lock()
			if p.seq == c.expected {
				c.expected++
			}
			c.readMu.Unlock()
			_ = c.sendPacket(flagACK, 0, c.expected, nil)
			c.setReadEOF()
			signal(c.dataCh)
			continue
		}
		if p.flags&flagData != 0 && len(p.payload) > 0 {
			c.processData(p.seq, p.payload)
			_ = c.sendPacket(flagACK, 0, c.expected, nil)
		}
	}
}

func (c *reliableConn) retransmitLoop() {
	t := time.NewTicker(tickEvery)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.writeMu.Lock()
			for _, p := range c.window {
				if time.Since(p.sent) >= c.rto {
					if p.tries >= maxRetries {
						c.writeMu.Unlock()
						c.setFatal(errors.New("quicproto: retransmission limit exceeded"))
						signal(c.dataCh)
						signal(c.ackCh)
						return
					}
					p.tries++
					p.sent = time.Now()
					_ = c.sendPacket(flagData, p.seq, c.currentExpected(), p.data)
				}
			}
			c.writeMu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// net.Conn 接口
// ---------------------------------------------------------------------------

func (c *reliableConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.readMu.Lock()
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			c.readMu.Unlock()
			return n, nil
		}
		err := c.readErr
		c.readMu.Unlock()
		if err != nil {
			return 0, err
		}
		if err := c.getFatal(); err != nil {
			return 0, err
		}

		var timer *time.Timer
		var timeoutCh <-chan time.Time
		if dl, ok := c.getDeadline(true); ok {
			d := time.Until(dl)
			if d <= 0 {
				return 0, &timeoutError{op: "read"}
			}
			timer = time.NewTimer(d)
			timeoutCh = timer.C
		}
		select {
		case <-c.dataCh:
		case <-timeoutCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, &timeoutError{op: "read"}
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			if err := c.getFatal(); err != nil && !errors.Is(err, net.ErrClosed) {
				return 0, err
			}
			return 0, io.EOF
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *reliableConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.getFatal(); err != nil {
		return 0, err
	}
	total := 0
	for total < len(p) {
		for len(c.window) >= windowSize {
			c.writeMu.Unlock()
			err := c.waitACK()
			c.writeMu.Lock()
			if err != nil {
				return total, err
			}
			if err := c.getFatal(); err != nil {
				return total, err
			}
		}
		chunk := p[total:]
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		seq := c.next
		c.next++
		pkt := &pendingPacket{
			seq:   seq,
			data:  append([]byte(nil), chunk...),
			sent:  time.Now(),
			tries: 1,
		}
		c.window[seq] = pkt
		if err := c.sendPacket(flagData, seq, c.currentExpected(), pkt.data); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

func (c *reliableConn) waitACK() error {
	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if dl, ok := c.getDeadline(false); ok {
		d := time.Until(dl)
		if d <= 0 {
			return &timeoutError{op: "write"}
		}
		timer = time.NewTimer(d)
		timeoutCh = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	select {
	case <-c.ackCh:
		return nil
	case <-timeoutCh:
		return &timeoutError{op: "write"}
	case <-c.done:
		return io.EOF
	}
}

func (c *reliableConn) Close() error {
	var closeErr error
	c.once.Do(func() {
		c.writeMu.Lock()
		seq := c.next
		c.next++
		_ = c.sendPacket(flagFIN, seq, c.currentExpected(), nil) // 尽力通知对端
		c.writeMu.Unlock()

		c.setFatal(net.ErrClosed)
		close(c.done)
		closeErr = c.udp.Close()
		signal(c.dataCh)
		signal(c.ackCh)
	})
	return closeErr
}

func (c *reliableConn) LocalAddr() net.Addr  { return c.udp.LocalAddr() }
func (c *reliableConn) RemoteAddr() net.Addr { return c.remote }

func (c *reliableConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *reliableConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	c.deadlineMu.Unlock()
	signal(c.dataCh)
	return nil
}

func (c *reliableConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	signal(c.ackCh)
	return nil
}

func (c *reliableConn) getDeadline(read bool) (time.Time, bool) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if read {
		return c.readDeadline, !c.readDeadline.IsZero()
	}
	return c.writeDeadline, !c.writeDeadline.IsZero()
}

func (c *reliableConn) setFatal(err error) {
	if err == nil {
		return
	}
	c.fatalMu.Lock()
	if c.fatalErr == nil {
		c.fatalErr = err
	}
	c.fatalMu.Unlock()
}

func (c *reliableConn) getFatal() error {
	c.fatalMu.Lock()
	defer c.fatalMu.Unlock()
	return c.fatalErr
}

func (c *reliableConn) setReadEOF() {
	c.readMu.Lock()
	if c.readErr == nil {
		c.readErr = io.EOF
	}
	c.readMu.Unlock()
}
