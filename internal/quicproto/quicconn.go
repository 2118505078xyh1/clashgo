package quicproto

// A minimal but real QUIC v1 client implemented on top of crypto/tls's
// QUICConn.  crypto/tls performs the TLS 1.3 handshake and key schedule; this
// file implements the QUIC packet layer: connection IDs, packet numbers,
// long/short headers, AEAD + header protection, frames, ACKs, CRYPTO
// retransmission and 1-RTT STREAM data.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	packetTypeInitial   = 0xc0 // 0b1100_0000
	packetTypeZeroRTT   = 0xd0
	packetTypeHandshake = 0xe0
	packetTypeRetry     = 0xf0

	quicVersion1            = 1
	pnBytes                 = 4
	minInitialDatagramSize  = 1200
	retransmitInterval      = 200 * time.Millisecond
	defaultHandshakeTimeout = 5 * time.Second

	// Congestion control (RFC 9002, simplified): the initial window is ten
	// maximum-size datagrams (10 * 1472 = 14720 bytes).
	defaultMTU      = 1472
	initialCwnd     = 10 * defaultMTU
	defaultSSThresh = 1 << 30

	// Key Phase is bit 2 of the short header's first byte (mask 0x04).
	keyPhaseBit = 0x04

	// Default ack delay exponent used when no transport parameter is known.
	defaultAckDelayExponent = 3
	defaultMaxAckDelay      = 25 * time.Millisecond
)

// queuedPacket is a fully protected packet waiting for congestion window
// credit.  The packet number is assigned at queue time so callers can track
// sent CRYPTO/STREAM data while the actual UDP write is deferred.
type queuedPacket struct {
	level tls.QUICEncryptionLevel
	pn    uint64
	data  []byte
	size  int
}

// sentPacketInfo records when a packet actually left the socket and how big
// it was, for RTT sampling and congestion window accounting.
type sentPacketInfo struct {
	sentAt time.Time
	size   int
}

type sentPacketKey struct {
	level tls.QUICEncryptionLevel
	pn    uint64
}

// unackedFrame remembers an application-level frame so PTO can retransmit it.
type unackedFrame struct {
	pn      uint64
	payload []byte
	sentAt  time.Time
}

// packetHeaderInfo carries the cleartext fields of a long header packet.
type packetHeaderInfo struct {
	isLong      bool
	typ         byte // packet type bits (masked with 0x30) for long headers
	version     uint32
	dcid        []byte
	scid        []byte
	token       []byte
	pnOffset    int // offset of packet number field in the protected packet
	lengthValue int // value of the length field
}

// makeLongHeader builds the unprotected header of a long header packet,
// including the PN field.  payloadLen is the length of the encrypted payload
// (after PADDING); the length field is set to pnLen + payloadLen + AEAD tag.
func makeLongHeader(typ byte, dcid, scid, token []byte, pn uint64, pnLen, payloadLen int) ([]byte, int) {
	h := make([]byte, 0, 64)
	h = append(h, typ|byte(pnLen-1))
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], quicVersion1)
	h = append(h, ver[:]...)
	h = appendVarint(h, uint64(len(dcid)))
	h = append(h, dcid...)
	h = appendVarint(h, uint64(len(scid)))
	h = append(h, scid...)
	if typ == packetTypeInitial {
		h = appendVarint(h, uint64(len(token)))
		h = append(h, token...)
	}
	h = appendVarint(h, uint64(pnLen+payloadLen+16))
	pnOffset := len(h)
	for i := pnLen - 1; i >= 0; i-- {
		h = append(h, byte(pn>>(uint(i)*8)))
	}
	return h, pnOffset
}

// makeShortHeader builds the unprotected header of a 1-RTT packet.
func makeShortHeader(dcid []byte, pn uint64, pnLen int, keyPhase byte) ([]byte, int) {
	h := make([]byte, 0, 32)
	// RFC 9000 §17.3.1: Key Phase is bit 2 (mask 0x04) of the first byte.
	h = append(h, (keyPhase&1)<<2|byte(pnLen-1))
	h = append(h, dcid...)
	pnOffset := len(h)
	for i := pnLen - 1; i >= 0; i-- {
		h = append(h, byte(pn>>(uint(i)*8)))
	}
	return h, pnOffset
}

// parseLongHeaderClear parses the cleartext portion of a long header packet.
// The packet type bits (bits 4-5 of the first byte) are NOT protected, so the
// encryption level can be determined before removing header protection.
func parseLongHeaderClear(data []byte) (packetHeaderInfo, error) {
	var info packetHeaderInfo
	if len(data) < 7 {
		return info, errors.New("quicproto: long header packet too short")
	}
	info.isLong = true
	// Bits 7-4 of the first byte are cleartext (bits 3-0 are HP-protected),
	// giving the full type prefix 0xc0/0xd0/0xe0/0xf0.
	info.typ = data[0] & 0xf0
	info.version = binary.BigEndian.Uint32(data[1:5])
	if info.version != quicVersion1 {
		return info, fmt.Errorf("quicproto: unsupported QUIC version 0x%08x", info.version)
	}
	idx := 5
	dcil, n, err := readVarint(data[idx:])
	if err != nil {
		return info, err
	}
	idx += n
	if uint64(len(data)-idx) < dcil {
		return info, errors.New("quicproto: truncated destination connection ID")
	}
	info.dcid = data[idx : idx+int(dcil)]
	idx += int(dcil)
	scil, n, err := readVarint(data[idx:])
	if err != nil {
		return info, err
	}
	idx += n
	if uint64(len(data)-idx) < scil {
		return info, errors.New("quicproto: truncated source connection ID")
	}
	info.scid = data[idx : idx+int(scil)]
	idx += int(scil)
	if info.typ == packetTypeRetry {
		// Retry has no Length or Packet Number field.  Everything after SCID
		// up to the final 16-byte integrity tag is the Retry Token.
		if len(data)-idx < 16 {
			return info, errors.New("quicproto: truncated Retry packet")
		}
		info.token = data[idx : len(data)-16]
		info.lengthValue = len(data) - idx // consume the whole Retry packet
		info.pnOffset = idx
		return info, nil
	}
	if info.typ == packetTypeInitial {
		tokenLen, n, err := readVarint(data[idx:])
		if err != nil {
			return info, err
		}
		idx += n
		if uint64(len(data)-idx) < tokenLen {
			return info, errors.New("quicproto: truncated token")
		}
		info.token = data[idx : idx+int(tokenLen)]
		idx += int(tokenLen)
	}
	length, n, err := readVarint(data[idx:])
	if err != nil {
		return info, err
	}
	idx += n
	info.lengthValue = int(length)
	info.pnOffset = idx
	return info, nil
}

// ackRangesFromPNs converts a set of packet numbers into ACK ranges.
func ackRangesFromPNs(pns []uint64) (uint64, []ackRange) {
	if len(pns) == 0 {
		return 0, nil
	}
	sort.Slice(pns, func(i, j int) bool { return pns[i] > pns[j] })
	largest := pns[0]
	type run struct{ high, low uint64 }
	var runs []run
	rh, rl := pns[0], uint64(1)
	for i := 1; i < len(pns); i++ {
		if pns[i] == pns[i-1]-1 {
			rl++
		} else {
			runs = append(runs, run{rh, pns[i-1]})
			rh, rl = pns[i], 1
		}
	}
	runs = append(runs, run{rh, pns[len(pns)-1]})
	var ranges []ackRange
	for i, r := range runs {
		var gap uint64
		if i > 0 {
			gap = runs[i-1].low - r.high - 1
		}
		// RFC 9000 §19.3.1: ACK Range Length = largest - smallest（连续包数 - 1），
		// Gap = 前一段 smallest - 本段 largest - 2。
		ranges = append(ranges, ackRange{gap: gap - 1, length: r.high - r.low})
	}
	return largest, ranges
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

type cryptoChunk struct {
	offset uint64
	data   []byte
}

type cryptoOutState struct {
	offset   uint64                   // next CRYPTO stream offset
	pending  []cryptoChunk            // not yet acknowledged
	sent     map[uint64][]cryptoChunk // packet number -> chunks sent in it
	lastSent time.Time
}

type quicConnection struct {
	conn       *net.UDPConn
	serverAddr *net.UDPAddr

	initialDCID []byte // DCID of the very first Initial packet (key derivation)
	scid        []byte // our source connection ID
	dcid        []byte // destination connection ID for non-Initial packets
	serverSCID  []byte // SCID learned from the server's Initial packet

	initialClientPP *packetProtection
	initialServerPP *packetProtection

	tls      *tls.QUICConn
	peerTP   *transportParameters
	clientTP []byte // 客户端 TP，供 QUICTransportParametersRequired 事件重设

	encrypt   map[tls.QUICEncryptionLevel]*packetProtection
	decrypt   map[tls.QUICEncryptionLevel]*packetProtection
	cryptoIn  map[tls.QUICEncryptionLevel]*cryptoBuffer
	cryptoOut map[tls.QUICEncryptionLevel]*cryptoOutState

	// forcedSuite overrides the suite reported by crypto/tls.  Set only by
	// dialQUICWithSuites so tests can exercise ChaCha20-Poly1305 end to end
	// (Go 1.27 deliberately ignores Config.CipherSuites for TLS 1.3).
	forcedSuite uint16

	pn          map[tls.QUICEncryptionLevel]uint64
	largestRecv map[tls.QUICEncryptionLevel]uint64
	recvPNs     map[tls.QUICEncryptionLevel]map[uint64]bool
	ackPending  map[tls.QUICEncryptionLevel]bool

	streams       map[uint64]*streamReassembler
	streamBuffers map[uint64]*streamBuffer

	handshakeDone bool

	// DATAGRAM (RFC 9000 §19.4) receive queue.  Datagrams are unreliable and
	// delivered in arrival order; a condition channel wakes blocked readers.
	datagrams  [][]byte
	datagramCh chan struct{}

	// Congestion control and RTT estimation (RFC 9002, simplified).
	cwnd          int
	bytesInFlight int
	ssthresh      int
	probeCredit   int // packets allowed past cwnd while a PTO probe is in flight
	smoothedRTT   time.Duration
	rttvar        time.Duration
	minRTT        time.Duration
	sendQueue     []queuedPacket
	sentPackets   map[sentPacketKey]sentPacketInfo
	unackedFrames []unackedFrame // STREAM frames eligible for PTO retransmit
	rttSampleUsed bool           // at most one RTT sample per ACK frame

	// Key update (RFC 9001 §6).
	localKeyPhase  byte
	peerKeyPhase   byte
	prevDecryptApp *packetProtection
	keyUpdateAcked bool // an ACK for the current local key phase was received

	// Retry / version negotiation.
	retryToken       []byte
	initialToken     []byte // token to place in the next Initial header
	versionConfirmed bool

	mu        sync.Mutex
	closeOnce sync.Once
	closeCh   chan struct{}
	err       error
}

// dialQUIC establishes a QUIC connection and completes the TLS handshake.
func dialQUIC(ctx context.Context, address, serverName, alpn string, skipVerify bool) (*quicConnection, error) {
	return dialQUICWithSuites(ctx, address, serverName, alpn, skipVerify, nil)
}

// dialQUICWithSuites is dialQUIC with an optional TLS cipher-suite restriction
// (used by tests to exercise ChaCha20-Poly1305 end to end).
func dialQUICWithSuites(ctx context.Context, address, serverName, alpn string, skipVerify bool, suites []uint16) (*quicConnection, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	initialDCID, err := randomBytes(16)
	if err != nil {
		conn.Close()
		return nil, err
	}
	scid, err := randomBytes(8)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ik := deriveInitialKeys(initialDCID)
	clientPP, err := newPacketProtectionFromRaw(ik.clientKey, ik.clientIV, ik.clientHP)
	if err != nil {
		conn.Close()
		return nil, err
	}
	serverPP, err := newPacketProtectionFromRaw(ik.serverKey, ik.serverIV, ik.serverHP)
	if err != nil {
		conn.Close()
		return nil, err
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS13,
		CipherSuites:       suites,
	}
	qc := tls.QUICClient(&tls.QUICConfig{TLSConfig: tlsConfig})
	var forced uint16
	if len(suites) == 1 {
		forced = suites[0]
	}

	c := &quicConnection{
		conn:             conn,
		serverAddr:       udpAddr,
		initialDCID:      initialDCID,
		scid:             scid,
		dcid:             append([]byte(nil), initialDCID...),
		initialClientPP:  clientPP,
		initialServerPP:  serverPP,
		tls:              qc,
		forcedSuite:      forced,
		encrypt:          map[tls.QUICEncryptionLevel]*packetProtection{},
		decrypt:          map[tls.QUICEncryptionLevel]*packetProtection{},
		cryptoIn:         map[tls.QUICEncryptionLevel]*cryptoBuffer{},
		cryptoOut:        map[tls.QUICEncryptionLevel]*cryptoOutState{},
		pn:               map[tls.QUICEncryptionLevel]uint64{},
		largestRecv:      map[tls.QUICEncryptionLevel]uint64{},
		recvPNs:          map[tls.QUICEncryptionLevel]map[uint64]bool{},
		ackPending:       map[tls.QUICEncryptionLevel]bool{},
		streams:          map[uint64]*streamReassembler{},
		streamBuffers:    map[uint64]*streamBuffer{},
		datagramCh:       make(chan struct{}, 1),
		cwnd:             initialCwnd,
		ssthresh:         defaultSSThresh,
		smoothedRTT:      333 * time.Millisecond, // RFC 9002 §6.2.2 initial RTT
		rttvar:           333 * time.Millisecond / 2,
		minRTT:           time.Duration(1 << 62),
		sentPackets:      map[sentPacketKey]sentPacketInfo{},
		versionConfirmed: false, // will be set once the version is confirmed
		closeCh:          make(chan struct{}),
	}
	for _, level := range []tls.QUICEncryptionLevel{tls.QUICEncryptionLevelInitial, tls.QUICEncryptionLevelHandshake, tls.QUICEncryptionLevelApplication} {
		c.cryptoIn[level] = &cryptoBuffer{}
		c.cryptoOut[level] = &cryptoOutState{sent: map[uint64][]cryptoChunk{}}
	}

	// Go 1.27 的 TLS QUIC 层在 ClientHello 构造时触发
	// QUICTransportParametersRequired；必须在该事件里设置 TP（quic-go 同样如此）。
	// 这里保留 Start 前的设置以兼容旧行为，并在事件里再次设置。
	qc.SetTransportParameters(encodeClientTransportParameters(scid))
	c.clientTP = encodeClientTransportParameters(scid)
	if err := qc.Start(context.Background()); err != nil {
		c.close()
		return nil, err
	}
	c.mu.Lock()
	err = c.processEventsLocked()
	c.mu.Unlock()
	if err != nil {
		c.close()
		return nil, err
	}
	if err := c.handshakeLoop(ctx); err != nil {
		c.close()
		return nil, err
	}
	go c.readLoop()
	go c.retransmitLoop()
	return c, nil
}

// ---------------------------------------------------------------------------
// TLS event processing
// ---------------------------------------------------------------------------

func (c *quicConnection) processEventsLocked() error {
	for {
		e := c.tls.NextEvent()
		switch e.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICSetWriteSecret, tls.QUICSetReadSecret:
			suite := e.Suite
			if c.forcedSuite != 0 {
				suite = c.forcedSuite
			}
			pp, err := newPacketProtection(append([]byte(nil), e.Data...), suite)
			if err != nil {
				return err
			}
			if e.Kind == tls.QUICSetWriteSecret {
				c.encrypt[e.Level] = pp
			} else {
				c.decrypt[e.Level] = pp
			}
		case tls.QUICTransportParametersRequired:
			// 必须在事件里设置（Go 1.27 quic-go 亦如此）。
			c.tls.SetTransportParameters(c.clientTP)
		case tls.QUICWriteData:
			if err := c.sendCryptoLocked(e.Level, e.Data); err != nil {
				return err
			}
		case tls.QUICTransportParameters:
			if len(e.Data) > 0 {
				if tp, err := parseTransportParameters(e.Data); err == nil {
					c.peerTP = tp
				}
			}
		case tls.QUICHandshakeDone:
			c.handshakeDone = true
			// The handshake was acknowledged by the peer, so the initial key
			// phase may be updated (RFC 9001 §6.1).
			c.keyUpdateAcked = true
			// 握手完成后丢弃 Initial/Handshake 级的未发包与重传状态
			// （RFC 9000 §6.5：这些密钥即将丢弃）。残留旧包会被服务端
			// 视为无效并触发 TRANSPORT_PARAMETER_ERROR。
			for _, l := range []tls.QUICEncryptionLevel{tls.QUICEncryptionLevelInitial, tls.QUICEncryptionLevelHandshake} {
				if out := c.cryptoOut[l]; out != nil {
					out.pending = nil
				}
			}
			kept := c.sendQueue[:0]
			for _, q := range c.sendQueue {
				if q.level != tls.QUICEncryptionLevelInitial && q.level != tls.QUICEncryptionLevelHandshake {
					kept = append(kept, q)
				}
			}
			c.sendQueue = kept
			// 握手期 PTO 反复把 cwnd 减半到最小窗口，且 Initial/Handshake 的
			// sentPackets 在密钥丢弃后永远不会收到 ACK。重置拥塞状态，否则
			// bytesInFlight 卡在高位、cwnd 卡在最小值，1-RTT STREAM 帧
			// 永远被 flushSendQueueLocked 的窗口检查挡住、发不出去。
			c.bytesInFlight = 0
			for key := range c.sentPackets {
				if key.level == tls.QUICEncryptionLevelInitial || key.level == tls.QUICEncryptionLevelHandshake {
					delete(c.sentPackets, key)
				}
			}
			c.cwnd = initialCwnd
			c.ssthresh = defaultSSThresh
		case tls.QUICErrorEvent:
			return e.Err
		}
	}
}

// ---------------------------------------------------------------------------
// Sending packets
// ---------------------------------------------------------------------------

// maxInitialCryptoData 是一次 Initial CRYPTO 帧能安全承载的最大字节数。
// Go 的 QUIC ClientHello 可达 1500+ 字节；单个 UDP 数据报超过 MTU 会被 IP
// 分片，而几乎所有公网 QUIC 服务端都会丢弃分片包。RFC 9000 §14.1 要求
// Initial 数据报至少 1200 字节，实现上必须把大 CRYPTO 数据拆成多个包。
// 1100 + 头(约40) + AEAD tag(16) + 帧开销(约5) ≈ 1161 < 1200，留有余量。
const maxInitialCryptoData = 1100

func (c *quicConnection) sendCryptoLocked(level tls.QUICEncryptionLevel, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	out := c.cryptoOut[level]
	startOff := out.offset
	out.offset += uint64(len(data))
	out.pending = append(out.pending, cryptoChunk{offset: startOff, data: append([]byte(nil), data...)})
	out.lastSent = time.Now()

	maxChunk := len(data)
	if level == tls.QUICEncryptionLevelInitial && maxChunk > maxInitialCryptoData {
		maxChunk = maxInitialCryptoData
	}
	// 登记整块 chunk（而非分片）：ACK 时 handleACKLocked 用 out.sent[pn]
	// 的 chunk 去匹配并清除 out.pending 里的整块。若登记分片会匹配失败，
	// 导致 out.pending 永不清空、CRYPTO 无限重传。
	fullChunk := cryptoChunk{offset: startOff, data: append([]byte(nil), data...)}
	for len(data) > 0 {
		n := len(data)
		if n > maxChunk {
			n = maxChunk
		}
		part := data[:n]
		payload := appendCryptoFrame(nil, startOff, part)
		pn, err := c.sendPacketLocked(level, payload)
		if err != nil {
			return err
		}
		out.sent[pn] = []cryptoChunk{fullChunk}
		startOff += uint64(n)
		data = data[n:]
	}
	return nil
}

// sendPacketLocked constructs and protects one QUIC packet, enqueues it and
// flushes as much of the queue as the congestion window allows.  It returns
// the packet number used.  c.mu must be held.  A full window does not fail the
// caller: the packet is sent later when ACKs open the window (or by the PTO
// timer), which keeps large transfers lossless.
func (c *quicConnection) sendPacketLocked(level tls.QUICEncryptionLevel, payload []byte) (uint64, error) {
	pn := c.pn[level]
	c.pn[level]++

	var pp *packetProtection
	var h []byte
	var pnOffset int
	switch level {
	case tls.QUICEncryptionLevelInitial:
		pp = c.initialClientPP
		// Pad the Initial datagram to the minimum required size.  Iterate
		// because the length varint can grow when PADDING is added.  After a
		// Retry the header DCID is the server's Retry SCID while the keys
		// remain derived from the original DCID (RFC 9000 §7.4.3).
		for {
			// RFC 9000 §7.2：客户端所有 Initial 包必须使用同一个 DCID，
			// 即最初随机生成的 initialDCID。收到服务端 Initial 后 c.dcid
			// 会切换为服务端 SCID（供 Handshake/1-RTT 用），但 Initial
			// 包不能用它，否则服务端视为无效连接。
			h, pnOffset = makeLongHeader(packetTypeInitial, c.initialDCID, c.scid, c.initialToken, pn, pnBytes, len(payload))
			total := len(h) + len(payload) + 16
			if total >= minInitialDatagramSize {
				break
			}
			payload = appendPaddingFrames(payload, minInitialDatagramSize-total)
		}
	case tls.QUICEncryptionLevelHandshake:
		pp = c.encrypt[level]
		if pp == nil {
			return 0, errors.New("quicproto: no Handshake write keys")
		}
		h, pnOffset = makeLongHeader(packetTypeHandshake, c.dcid, c.scid, nil, pn, pnBytes, len(payload))
	case tls.QUICEncryptionLevelApplication:
		pp = c.encrypt[level]
		if pp == nil {
			return 0, errors.New("quicproto: no Application write keys")
		}
		h, pnOffset = makeShortHeader(c.dcid, pn, pnBytes, c.localKeyPhase)
	default:
		return 0, fmt.Errorf("quicproto: cannot send at level %v", level)
	}

	pkt, err := pp.seal(h, pnOffset, pnBytes, payload, pn)
	if err != nil {
		return 0, err
	}

	// Remember STREAM frames for PTO retransmission. DATAGRAM and ACK frames
	// are deliberately excluded: datagrams are never retransmitted (§19.4).
	if level == tls.QUICEncryptionLevelApplication && len(payload) > 0 && payload[0]&0xf8 == frameStream {
		c.unackedFrames = append(c.unackedFrames, unackedFrame{
			pn:      pn,
			payload: append([]byte(nil), payload...),
			sentAt:  time.Now(),
		})
	}

	c.sendQueue = append(c.sendQueue, queuedPacket{level: level, pn: pn, data: pkt, size: len(pkt)})
	return pn, c.flushSendQueueLocked()
}

// flushSendQueueLocked writes queued packets while the congestion window has
// credit.  c.mu must be held.
func (c *quicConnection) flushSendQueueLocked() error {
	for len(c.sendQueue) > 0 {
		q := c.sendQueue[0]
		if c.bytesInFlight > 0 && c.bytesInFlight+q.size > c.cwnd && c.probeCredit <= 0 {
			break // window full: wait for an ACK or the PTO timer
		}
		if c.bytesInFlight+q.size > c.cwnd && c.probeCredit > 0 {
			c.probeCredit-- // RFC 9002 §6.2.4: PTO probes may exceed the window
		}
		if _, err := c.conn.WriteToUDP(q.data, c.serverAddr); err != nil {
			return err
		}
		c.bytesInFlight += q.size
		c.sentPackets[sentPacketKey{level: q.level, pn: q.pn}] = sentPacketInfo{
			sentAt: time.Now(),
			size:   q.size,
		}
		c.sendQueue = c.sendQueue[1:]
	}
	return nil
}

func (c *quicConnection) flushACKsLocked() {
	for level, pending := range c.ackPending {
		if !pending || len(c.recvPNs[level]) == 0 {
			continue
		}
		pns := make([]uint64, 0, len(c.recvPNs[level]))
		for pn := range c.recvPNs[level] {
			pns = append(pns, pn)
		}
		largest, ranges := ackRangesFromPNs(pns)
		payload := appendACKFrame(nil, largest, 0, ranges)
		if _, err := c.sendPacketLocked(level, payload); err == nil {
			c.ackPending[level] = false
			c.recvPNs[level] = make(map[uint64]bool)
		}
	}
}

// ---------------------------------------------------------------------------
// Receiving packets
// ---------------------------------------------------------------------------

func (c *quicConnection) handshakeLoop(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultHandshakeTimeout)
	}
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	defer c.conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 65535)
	for {
		select {
		case <-c.closeCh:
			return errors.New("quicproto: connection closed during handshake")
		default:
		}
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		c.mu.Lock()
		err = c.handleDatagramLocked(buf[:n])
		if err == nil {
			c.flushACKsLocked()
		}
		done := c.handshakeDone
		c.mu.Unlock()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (c *quicConnection) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.closeCh:
			default:
				c.mu.Lock()
				c.err = err
				for _, sb := range c.streamBuffers {
					sb.closeWith(err)
				}
				c.mu.Unlock()
			}
			return
		}
		c.mu.Lock()
		_ = c.handleDatagramLocked(buf[:n])
		c.flushACKsLocked()
		c.mu.Unlock()
	}
}

func (c *quicConnection) retransmitLoop() {
	ticker := time.NewTicker(retransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			pto := c.ptoDuration()

			// Unacknowledged CRYPTO data at Initial / Handshake levels.
			for _, level := range []tls.QUICEncryptionLevel{tls.QUICEncryptionLevelInitial, tls.QUICEncryptionLevelHandshake} {
				out := c.cryptoOut[level]
				if out == nil || len(out.pending) == 0 || time.Since(out.lastSent) < pto {
					continue
				}
				chunks := append([]cryptoChunk(nil), out.pending...)
				// CRYPTO 重传同样要分片，否则 Initial 数据报超 MTU 被丢弃。
				limit := 1 << 30
				if level == tls.QUICEncryptionLevelInitial {
					limit = maxInitialCryptoData
				}
				c.probeCredit = 1
				for _, ch := range chunks {
					off := ch.offset
					remaining := ch.data
					for len(remaining) > 0 {
						n := len(remaining)
						if n > limit {
							n = limit
						}
						part := remaining[:n]
						pn, err := c.sendPacketLocked(level, appendCryptoFrame(nil, off, part))
						if err == nil {
							// 登记整块 ch（与 out.pending 一致），ACK 才能清除。
							out.sent[pn] = []cryptoChunk{ch}
							out.lastSent = time.Now()
							c.onLossLocked()
						}
						off += uint64(n)
						remaining = remaining[n:]
					}
				}
			}

			// Unacknowledged STREAM frames at the Application level (PTO,
			// RFC 9002 §6.2). Retransmission is idempotent thanks to the
			// stream reassembler's offset tracking.
			for i := 0; i < len(c.unackedFrames); {
				f := c.unackedFrames[i]
				if time.Since(f.sentAt) < pto {
					i++
					continue
				}
				payload := append([]byte(nil), f.payload...)
				c.unackedFrames = append(c.unackedFrames[:i], c.unackedFrames[i+1:]...)
				c.probeCredit = 1
				if _, err := c.sendPacketLocked(tls.QUICEncryptionLevelApplication, payload); err != nil {
					break
				}
				c.onLossLocked()
				// The retransmission re-registers itself with a fresh PN/sentAt.
			}

			// A full congestion window can also drain on a timer when ACKs
			// are delayed; keep flushing so the transfer never stalls.
			if len(c.sendQueue) > 0 && c.bytesInFlight >= c.cwnd {
				c.probeCredit = 1
			}
			_ = c.flushSendQueueLocked()
			c.mu.Unlock()
		}
	}
}

// onLossLocked applies a simple congestion response to a PTO/loss signal.
func (c *quicConnection) onLossLocked() {
	c.ssthresh = c.cwnd / 2
	if c.ssthresh < defaultMTU {
		c.ssthresh = defaultMTU
	}
	c.cwnd = c.ssthresh
}

func (c *quicConnection) handleDatagramLocked(datagram []byte) error {
	for len(datagram) > 0 {
		if datagram[0]&0x80 == 0 {
			if err := c.processPacketLocked(datagram, packetHeaderInfo{isLong: false}); err != nil {
				return err
			}
			return nil // short header packet must be the last in a datagram
		}
		// Version Negotiation: header form = 1, 32-bit version = 0 (§6).
		if len(datagram) >= 5 && binary.BigEndian.Uint32(datagram[1:5]) == 0 {
			return c.handleVersionNegotiationLocked(datagram)
		}
		info, err := parseLongHeaderClear(datagram)
		if err != nil {
			return err
		}
		end := info.pnOffset + info.lengthValue
		if end > len(datagram) {
			return errors.New("quicproto: QUIC packet length exceeds datagram")
		}
		if info.typ == packetTypeRetry {
			return c.handleRetryLocked(datagram[:end], info)
		}
		if err := c.processPacketLocked(datagram[:end], info); err != nil {
			return err
		}
		datagram = datagram[end:]
	}
	return nil
}

// openApplicationLocked removes header protection and decrypts a 1-RTT packet,
// trying the current, next and previous key generations.  RFC 9001 §6.1 keeps
// the header protection key unchanged across updates, so the Key Phase bit can
// be read before knowing which AEAD key to use.
func (c *quicConnection) openApplicationLocked(pkt []byte, pnOffset int, largest uint64) (fullPN uint64, pnLen int, header, payload []byte, err error) {
	cur := c.decrypt[tls.QUICEncryptionLevelApplication]
	if cur == nil {
		return 0, 0, nil, nil, errors.New("quicproto: no Application read keys")
	}
	phase := byte(0)
	if mask, mErr := cur.hpMask(pkt, pnOffset); mErr == nil {
		phase = (pkt[0] ^ (mask[0] & 0x1f)) & keyPhaseBit
	}

	type candidate struct {
		pp   *packetProtection
		kind int // 0 = current, 1 = next, 2 = previous
	}
	cands := []candidate{{cur, 0}}
	if next, nerr := cur.update(); nerr == nil {
		cands = append(cands, candidate{next, 1})
	}
	if c.prevDecryptApp != nil {
		cands = append(cands, candidate{c.prevDecryptApp, 2})
	}

	var lastErr error
	for _, cd := range cands {
		fullPN, pnLen, header, payload, err = cd.pp.openFull(pkt, pnOffset, false, largest)
		if err != nil {
			lastErr = err
			continue
		}
		if phase != c.peerKeyPhase {
			switch cd.kind {
			case 1: // peer initiated an update
				c.prevDecryptApp = cur
				c.decrypt[tls.QUICEncryptionLevelApplication] = cd.pp
			case 2: // late packet from the previous generation
				c.decrypt[tls.QUICEncryptionLevelApplication] = cd.pp
				c.prevDecryptApp = cur
			}
			c.peerKeyPhase = phase
		}
		return fullPN, pnLen, header, payload, nil
	}
	return 0, 0, nil, nil, lastErr
}

func (c *quicConnection) processPacketLocked(pkt []byte, info packetHeaderInfo) error {
	var level tls.QUICEncryptionLevel
	var pp *packetProtection
	var pnOffset int
	if info.isLong {
		switch info.typ {
		case packetTypeInitial:
			level, pp = tls.QUICEncryptionLevelInitial, c.initialServerPP
		case packetTypeHandshake:
			level, pp = tls.QUICEncryptionLevelHandshake, c.decrypt[tls.QUICEncryptionLevelHandshake]
		default:
			return fmt.Errorf("quicproto: unsupported long header type 0x%02x", info.typ)
		}
		if pp == nil {
			// 乱序：某加密级别的密钥尚未派生（典型于 coalesced/重排的数据报）。
			// 忽略而非报错，等待重传或后续包含 CRYPTO 的包。
			return nil
		}
		pnOffset = info.pnOffset
	} else {
		level = tls.QUICEncryptionLevelApplication
		// 1-RTT 包可能早于握手 CRYPTO 数据到达（coalesced/reordering）。
		// 此时还没有 Application 读密钥，忽略即可——真正的数据会重传。
		if c.decrypt[level] == nil {
			return nil
		}
		// 短首包无 DCIL 字段：DCID 长度对端已知（=我们 Initial 包的 SCID）。
		// 服务端发的短首包 DCID = 我们的 SCID，不是 c.dcid（那是服务端自己的 SCID）。
		pnOffset = 1 + len(c.scid)
	}

	var fullPN uint64
	var payload []byte
	var err error
	if info.isLong {
		fullPN, _, _, payload, err = pp.openFull(pkt, pnOffset, true, c.largestRecv[level])
	} else {
		fullPN, _, _, payload, err = c.openApplicationLocked(pkt, pnOffset, c.largestRecv[level])
		pp = c.decrypt[tls.QUICEncryptionLevelApplication]
	}
	if err != nil {
		return err
	}
	if fullPN > c.largestRecv[level] {
		c.largestRecv[level] = fullPN
	}

	// Learn the server's chosen SCID from its Initial packet and use it as
	// the DCID for all subsequent (non-Initial) packets.  Initial keys stay
	// bound to the ORIGINAL destination CID (RFC 9001 §5.2).
	if info.isLong && info.typ == packetTypeInitial && len(c.serverSCID) == 0 {
		c.serverSCID = append([]byte(nil), info.scid...)
		c.dcid = append([]byte(nil), info.scid...)
	}

	frames, err := parseFrames(payload)
	if err != nil {
		return err
	}
	ackable := false
	for _, f := range frames {
		switch f.typ {
		case frameCrypto:
			ackable = true
			contiguous := c.cryptoIn[level].add(f.crypto.offset, f.crypto.data)
			if len(contiguous) > 0 {
				if err := c.tls.HandleData(level, contiguous); err != nil {
					return err
				}
				if err := c.processEventsLocked(); err != nil {
					return err
				}
			}
		case frameACK:
			c.rttSampleUsed = false // one sample per ACK frame
			c.handleACKLocked(level, f.ack)
		case frameStream:
			ackable = true
			sr := c.streams[f.stream.streamID]
			if sr == nil {
				sr = &streamReassembler{}
				c.streams[f.stream.streamID] = sr
			}
			data := sr.add(f.stream.offset, f.stream.data, f.stream.fin)
			if len(data) > 0 {
				sb := c.getStreamBuffer(f.stream.streamID)
				sb.push(data)
				if sr.fin && sr.readOffset >= sr.finOffset {
					sb.closeWith(nil)
				}
			}
		case frameDatagram:
			// DATAGRAMs are unreliable: deliver to the queue but never ACK.
			c.pushDatagramLocked(f.datagram)
		case frameConnectionClose, 0x1d:
			// 之前曾忽略握手后的 Initial/Handshake CLOSE，结果把服务端的
			// 明确拒绝（如 invalid first ACK range）吞掉，误以为连接还活着。
			// 现在一律传播错误，让上层能看到真实失败原因。
			return fmt.Errorf("quicproto: connection closed by peer (0x%x): %s", f.code, f.reason)
		}
	}
	if ackable {
		if c.recvPNs[level] == nil {
			c.recvPNs[level] = make(map[uint64]bool)
		}
		c.recvPNs[level][fullPN] = true
		c.ackPending[level] = true
	}
	return nil
}

func (c *quicConnection) handleACKLocked(level tls.QUICEncryptionLevel, af *ackFrameData) {
	// Take at most one RTT sample per ACK frame, from the largest acknowledged
	// packet (RFC 9002 §6.2.1).
	if !c.rttSampleUsed && len(af.packets) > 0 {
		c.rttSampleUsed = true
		if info, ok := c.sentPackets[sentPacketKey{level: level, pn: af.packets[0]}]; ok {
			delay := time.Duration(af.delay) * (1 << defaultAckDelayExponent) * time.Microsecond
			rtt := time.Since(info.sentAt) - delay
			if rtt < 0 {
				rtt = 0
			}
			c.updateRTTRTTVar(rtt)
		}
	}

	var ackedBytes int
	for _, pn := range af.packets {
		key := sentPacketKey{level: level, pn: pn}
		if info, ok := c.sentPackets[key]; ok {
			ackedBytes += info.size
			c.bytesInFlight -= info.size
			if c.bytesInFlight < 0 {
				c.bytesInFlight = 0
			}
			delete(c.sentPackets, key)
		}
		// Drop remembered STREAM frames that are now acknowledged.
		for i := len(c.unackedFrames) - 1; i >= 0; i-- {
			if c.unackedFrames[i].pn == pn {
				c.unackedFrames = append(c.unackedFrames[:i], c.unackedFrames[i+1:]...)
			}
		}
		if level == tls.QUICEncryptionLevelApplication {
			c.keyUpdateAcked = true
		}
	}

	// Congestion control: slow start until ssthresh, then additive increase
	// (RFC 9002 §7).  A real stack also reacts to loss; here PTO acts as the
	// loss signal (see retransmitLoop).
	if ackedBytes > 0 {
		if c.cwnd < c.ssthresh {
			c.cwnd += ackedBytes
		} else {
			c.cwnd += defaultMTU * defaultMTU / c.cwnd
		}
		if c.cwnd > 1<<30 {
			c.cwnd = 1 << 30
		}
	}

	// 已确认的 STREAM 帧从 PTO 重传列表移除，避免无限重传风暴。
	if len(af.packets) > 0 {
		acked := make(map[uint64]bool, len(af.packets))
		for _, pn := range af.packets {
			acked[pn] = true
		}
		for i := len(c.unackedFrames) - 1; i >= 0; i-- {
			if acked[c.unackedFrames[i].pn] {
				c.unackedFrames = append(c.unackedFrames[:i], c.unackedFrames[i+1:]...)
			}
		}
	}

	out := c.cryptoOut[level]
	if out != nil {
		for _, pn := range af.packets {
			chunks, ok := out.sent[pn]
			if !ok {
				continue
			}
			for _, ch := range chunks {
				for i, p := range out.pending {
					if p.offset == ch.offset && bytes.Equal(p.data, ch.data) {
						out.pending = append(out.pending[:i], out.pending[i+1:]...)
						break
					}
				}
			}
			delete(out.sent, pn)
		}
	}

	// Newly opened window credit may allow queued packets to go out.
	_ = c.flushSendQueueLocked()
}

// updateRTTRTTVar applies the RFC 6298 / RFC 9002 §6.2.1 RTT estimators.
func (c *quicConnection) updateRTTRTTVar(rtt time.Duration) {
	if c.minRTT == time.Duration(1<<62) { // first sample
		c.smoothedRTT = rtt
		c.rttvar = rtt / 2
		c.minRTT = rtt
		return
	}
	diff := c.smoothedRTT - rtt
	if diff < 0 {
		diff = -diff
	}
	c.rttvar = c.rttvar*3/4 + diff/4
	c.smoothedRTT = c.smoothedRTT*7/8 + rtt/8
	if rtt < c.minRTT {
		c.minRTT = rtt
	}
}

// ptoDuration returns the probe timeout: smoothed RTT + 4 * RTT variance +
// the peer's max ACK delay (RFC 9002 §6.2.2, simplified).
func (c *quicConnection) ptoDuration() time.Duration {
	pto := c.smoothedRTT + 4*c.rttvar + defaultMaxAckDelay
	if pto < 100*time.Millisecond {
		pto = 100 * time.Millisecond
	}
	return pto
}

// ---------------------------------------------------------------------------
// DATAGRAM (RFC 9000 §19.4)
// ---------------------------------------------------------------------------

// pushDatagramLocked queues a received DATAGRAM payload and wakes readers.
// c.mu must be held.
func (c *quicConnection) pushDatagramLocked(data []byte) {
	c.datagrams = append(c.datagrams, append([]byte(nil), data...))
	select {
	case c.datagramCh <- struct{}{}:
	default:
	}
}

// SendDatagram sends one unreliable DATAGRAM frame at the Application
// encryption level.  DATAGRAMs are only available after the handshake.
func (c *quicConnection) SendDatagram(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.handshakeDone {
		return errors.New("quicproto: DATAGRAM requires a completed handshake")
	}
	if c.conn == nil {
		return net.ErrClosed
	}
	_, err := c.sendPacketLocked(tls.QUICEncryptionLevelApplication, appendDatagramFrame(nil, payload))
	return err
}

// ReceiveDatagram blocks until a DATAGRAM arrives, ctx is cancelled, or the
// connection closes.  Each call returns exactly one datagram payload.
func (c *quicConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		c.mu.Lock()
		if len(c.datagrams) > 0 {
			d := c.datagrams[0]
			c.datagrams[0] = nil
			c.datagrams = c.datagrams[1:]
			c.mu.Unlock()
			return d, nil
		}
		c.mu.Unlock()
		select {
		case <-c.datagramCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.closeCh:
			return nil, net.ErrClosed
		}
	}
}

// ---------------------------------------------------------------------------
// Key update (RFC 9001 §6)
// ---------------------------------------------------------------------------

// InitiateKeyUpdate rotates the 1-RTT write AND read secrets to the next key
// generation (RFC 9001 §6.1), toggles the local Key Phase bit and sends a PING
// to signal the peer.  The peer's response triggers a receive-side update if
// it has not already been applied.
func (c *quicConnection) InitiateKeyUpdate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.handshakeDone {
		return errors.New("quicproto: key update requires a completed handshake")
	}
	if !c.keyUpdateAcked {
		return errors.New("quicproto: key update requires an ACK for the current key phase")
	}
	writeKey := c.encrypt[tls.QUICEncryptionLevelApplication]
	readKey := c.decrypt[tls.QUICEncryptionLevelApplication]
	if writeKey == nil || readKey == nil {
		return errors.New("quicproto: missing Application keys")
	}
	nextWrite, err := writeKey.update()
	if err != nil {
		return err
	}
	nextRead, err := readKey.update()
	if err != nil {
		return err
	}
	c.prevDecryptApp = readKey
	c.decrypt[tls.QUICEncryptionLevelApplication] = nextRead
	c.encrypt[tls.QUICEncryptionLevelApplication] = nextWrite
	c.localKeyPhase ^= 1
	c.peerKeyPhase ^= keyPhaseBit
	c.keyUpdateAcked = false

	// A PING is the lightest frame that can carry the new key phase.
	_, err = c.sendPacketLocked(tls.QUICEncryptionLevelApplication, []byte{0x01})
	return err
}

// ExportKeyingMaterial exposes the underlying TLS RFC 5705 exporter for
// protocol authentication (e.g. TUIC v5 uses label=<UUID>, context=<password>,
// length=32).  crypto/tls declares ExportKeyingMaterial on *ConnectionState,
// so the value returned by ConnectionState() must be made addressable first.
func (c *quicConnection) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	cs := c.tls.ConnectionState()
	return cs.ExportKeyingMaterial(label, context, length)
}

// ---------------------------------------------------------------------------
// Retry (RFC 9000 §7.4)
// ---------------------------------------------------------------------------

// verifyRetryIntegrity checks the Retry Integrity Tag defined in RFC 9001 §5.8.
func verifyRetryIntegrity(pkt, odcid []byte) bool {
	if len(pkt) < 16 || len(odcid) > 255 {
		return false
	}
	body, tag := pkt[:len(pkt)-16], pkt[len(pkt)-16:]
	key := []byte{
		0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
		0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
	}
	nonce := []byte{
		0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
		0x23, 0x98, 0x25, 0xbb,
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	aad := make([]byte, 0, 1+len(odcid)+len(body))
	aad = append(aad, byte(len(odcid)))
	aad = append(aad, odcid...)
	aad = append(aad, body...)
	expected := aead.Seal(nil, nonce, nil, aad) // empty plaintext -> 16-byte tag
	return subtle.ConstantTimeCompare(expected, tag) == 1
}

// handleRetryLocked processes a Retry packet: it installs the Retry's Source
// Connection ID as the new DCID, stores the token, re-derives Initial keys and
// resends the Initial flight (with the token) in a fresh packet number space.
func (c *quicConnection) handleRetryLocked(pkt []byte, info packetHeaderInfo) error {
	if !verifyRetryIntegrity(pkt, c.initialDCID) {
		return errors.New("quicproto: invalid Retry integrity tag")
	}
	c.serverSCID = append([]byte(nil), info.scid...)
	c.dcid = append([]byte(nil), info.scid...)
	c.retryToken = append([]byte(nil), info.token...)
	c.initialToken = c.retryToken

	// Re-derive the Initial keys.  RFC 9001 §5.2 keeps them bound to the
	// ORIGINAL DCID, so the values are unchanged; rebuilding the objects makes
	// the key-schedule restart explicit.
	ik := deriveInitialKeys(c.initialDCID)
	clientPP, err := newPacketProtectionFromRaw(ik.clientKey, ik.clientIV, ik.clientHP)
	if err != nil {
		return err
	}
	serverPP, err := newPacketProtectionFromRaw(ik.serverKey, ik.serverIV, ik.serverHP)
	if err != nil {
		return err
	}
	c.initialClientPP, c.initialServerPP = clientPP, serverPP

	// Reset the Initial packet number space and resend the ClientHello.
	c.pn[tls.QUICEncryptionLevelInitial] = 0
	c.largestRecv[tls.QUICEncryptionLevelInitial] = 0
	c.recvPNs[tls.QUICEncryptionLevelInitial] = make(map[uint64]bool)
	c.ackPending[tls.QUICEncryptionLevelInitial] = false

	out := c.cryptoOut[tls.QUICEncryptionLevelInitial]
	var chunks []cryptoChunk
	if out != nil {
		chunks = append(chunks, out.pending...)
		if len(chunks) == 0 { // already ACKed: fall back to all sent chunks
			for _, sent := range out.sent {
				chunks = append(chunks, sent...)
			}
			sort.Slice(chunks, func(i, j int) bool { return chunks[i].offset < chunks[j].offset })
		}
	}
	if len(chunks) > 0 {
		payload := []byte(nil)
		for _, ch := range chunks {
			payload = appendCryptoFrame(payload, ch.offset, ch.data)
		}
		if _, err := c.sendPacketLocked(tls.QUICEncryptionLevelInitial, payload); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Version negotiation (RFC 9000 §6)
// ---------------------------------------------------------------------------

// handleVersionNegotiationLocked parses a version=0 packet and, if v1 is
// offered, restarts the Initial flight with version 1 (RFC 9000 §6.3).
func (c *quicConnection) handleVersionNegotiationLocked(pkt []byte) error {
	if c.versionConfirmed {
		return nil // we only ever offer v1; an echo of v1 is a no-op
	}
	if len(pkt) < 5 {
		return errors.New("quicproto: truncated Version Negotiation packet")
	}
	idx := 5
	dcil, n, err := readVarint(pkt[idx:])
	if err != nil {
		return err
	}
	idx += n
	if idx+int(dcil) > len(pkt) {
		return errors.New("quicproto: truncated VN destination CID")
	}
	idx += int(dcil)
	scil, n, err := readVarint(pkt[idx:])
	if err != nil {
		return err
	}
	idx += n
	if idx+int(scil) > len(pkt) {
		return errors.New("quicproto: truncated VN source CID")
	}
	idx += int(scil)

	foundV1 := false
	for idx+4 <= len(pkt) {
		if binary.BigEndian.Uint32(pkt[idx:idx+4]) == quicVersion1 {
			foundV1 = true
		}
		idx += 4
	}
	if !foundV1 {
		return errors.New("quicproto: no compatible QUIC version offered")
	}

	c.versionConfirmed = true
	c.initialToken = nil
	c.pn[tls.QUICEncryptionLevelInitial] = 0
	c.largestRecv[tls.QUICEncryptionLevelInitial] = 0
	c.recvPNs[tls.QUICEncryptionLevelInitial] = make(map[uint64]bool)
	c.ackPending[tls.QUICEncryptionLevelInitial] = false

	out := c.cryptoOut[tls.QUICEncryptionLevelInitial]
	if out != nil && len(out.pending) > 0 {
		payload := []byte(nil)
		for _, ch := range out.pending {
			payload = appendCryptoFrame(payload, ch.offset, ch.data)
		}
		if _, err := c.sendPacketLocked(tls.QUICEncryptionLevelInitial, payload); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

func (c *quicConnection) close() {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.conn != nil {
			c.conn.Close()
		}
		if c.tls != nil {
			_ = c.tls.Close()
		}
		c.mu.Lock()
		err := c.err
		if err == nil {
			err = net.ErrClosed
		}
		for _, sb := range c.streamBuffers {
			sb.closeWith(err)
		}
		c.mu.Unlock()
	})
}

func (c *quicConnection) setError(err error) {
	c.mu.Lock()
	c.err = err
	for _, sb := range c.streamBuffers {
		sb.closeWith(err)
	}
	c.mu.Unlock()
}
