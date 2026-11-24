package quicproto

// Local end-to-end validation of the QUIC packet stack.  The TLS layer is the
// real crypto/tls QUICServer/QUICClient; only the QUIC packet/framing layer is
// implemented here.  A successful handshake proves CRYPTO frames, AEAD,
// header protection, packet numbers, connection IDs and reassembly all work.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Minimal local QUIC echo server built on tls.QUICServer
// ---------------------------------------------------------------------------

type testQUICServer struct {
	conn       *net.UDPConn
	clientAddr *net.UDPAddr
	qc         *tls.QUICConn

	clientDCID []byte
	clientSCID []byte
	serverSCID []byte

	initialClientPP *packetProtection // decrypt client Initial
	initialServerPP *packetProtection // encrypt server Initial

	encrypt   map[tls.QUICEncryptionLevel]*packetProtection
	decrypt   map[tls.QUICEncryptionLevel]*packetProtection
	cryptoIn  map[tls.QUICEncryptionLevel]*cryptoBuffer
	cryptoOut map[tls.QUICEncryptionLevel]*cryptoOutState

	pn          map[tls.QUICEncryptionLevel]uint64
	largestRecv map[tls.QUICEncryptionLevel]uint64
	recvPNs     map[tls.QUICEncryptionLevel]map[uint64]bool
	ackPending  map[tls.QUICEncryptionLevel]bool

	echoOffset uint64
	gotEcho    chan []byte
	done       chan struct{}
}

func makeTestCertificate() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

func startTestQUICServer(t *testing.T) (*testQUICServer, error) {
	cert, err := makeTestCertificate()
	if err != nil {
		return nil, err
	}
	serverSCID, err := randomBytes(8)
	if err != nil {
		return nil, err
	}
	qc := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
	}})
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	s := &testQUICServer{
		conn:        conn,
		qc:          qc,
		serverSCID:  serverSCID,
		encrypt:     map[tls.QUICEncryptionLevel]*packetProtection{},
		decrypt:     map[tls.QUICEncryptionLevel]*packetProtection{},
		cryptoIn:    map[tls.QUICEncryptionLevel]*cryptoBuffer{},
		cryptoOut:   map[tls.QUICEncryptionLevel]*cryptoOutState{},
		pn:          map[tls.QUICEncryptionLevel]uint64{},
		largestRecv: map[tls.QUICEncryptionLevel]uint64{},
		recvPNs:     map[tls.QUICEncryptionLevel]map[uint64]bool{},
		ackPending:  map[tls.QUICEncryptionLevel]bool{},
		gotEcho:     make(chan []byte, 16),
		done:        make(chan struct{}),
	}
	for _, level := range []tls.QUICEncryptionLevel{tls.QUICEncryptionLevelInitial, tls.QUICEncryptionLevelHandshake, tls.QUICEncryptionLevelApplication} {
		s.cryptoIn[level] = &cryptoBuffer{}
		s.cryptoOut[level] = &cryptoOutState{sent: map[uint64][]cryptoChunk{}}
	}
	// Go's TLS layer treats transport parameters as opaque bytes, so the
	// original_destination_connection_id is not needed for this local test.
	qc.SetTransportParameters(encodeServerTransportParameters(serverSCID, nil))
	if err := qc.Start(context.Background()); err != nil {
		conn.Close()
		return nil, err
	}
	go s.serve()
	return s, nil
}

func (s *testQUICServer) serve() {
	defer close(s.done)
	buf := make([]byte, 65535)

	// First datagram: the client's Initial containing the ClientHello.
	n, addr, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return
	}
	s.clientAddr = addr
	info, err := parseLongHeaderClear(buf[:n])
	if err != nil {
		return
	}
	if info.typ != packetTypeInitial {
		return
	}
	s.clientDCID = append([]byte(nil), info.dcid...)
	s.clientSCID = append([]byte(nil), info.scid...)
	ik := deriveInitialKeys(s.clientDCID)
	s.initialClientPP, err = newPacketProtectionFromRaw(ik.clientKey, ik.clientIV, ik.clientHP)
	if err != nil {
		return
	}
	s.initialServerPP, err = newPacketProtectionFromRaw(ik.serverKey, ik.serverIV, ik.serverHP)
	if err != nil {
		return
	}

	// Feed the first datagram to TLS; this triggers the server's first flight.
	s.handleDatagram(buf[:n])

	for {
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.handleDatagram(buf[:n])
	}
}

func (s *testQUICServer) handleDatagram(datagram []byte) {
	for len(datagram) > 0 {
		if datagram[0]&0x80 == 0 {
			s.processPacket(datagram, packetHeaderInfo{isLong: false})
			return
		}
		info, err := parseLongHeaderClear(datagram)
		if err != nil {
			return
		}
		end := info.pnOffset + info.lengthValue
		if end > len(datagram) {
			return
		}
		s.processPacket(datagram[:end], info)
		datagram = datagram[end:]
	}
	s.flushACKs()
}

func (s *testQUICServer) processPacket(pkt []byte, info packetHeaderInfo) {
	var level tls.QUICEncryptionLevel
	var pp *packetProtection
	var pnOffset int
	if info.isLong {
		switch info.typ {
		case packetTypeInitial:
			level, pp = tls.QUICEncryptionLevelInitial, s.initialClientPP
		case packetTypeHandshake:
			level, pp = tls.QUICEncryptionLevelHandshake, s.decrypt[tls.QUICEncryptionLevelHandshake]
		default:
			return
		}
		pnOffset = info.pnOffset
	} else {
		level, pp = tls.QUICEncryptionLevelApplication, s.decrypt[tls.QUICEncryptionLevelApplication]
		pnOffset = 1 + len(s.clientSCID)
	}
	if pp == nil {
		return
	}
	pn, _, payload, err := pp.open(pkt, pnOffset, info.isLong)
	if err != nil {
		return
	}
	// The server always sends 4-byte packet numbers; recover pnLen for the
	// decode window from the first byte.
	pnLen := 4
	if len(pkt) > 0 {
		mask, mErr := pp.hpMask(pkt, pnOffset)
		if mErr == nil {
			hpBits := byte(0x0f)
			if !info.isLong {
				hpBits = 0x1f
			}
			pnLen = int((pkt[0]^(mask[0]&hpBits))&0x03) + 1
		}
	}
	fullPN := decodePacketNumber(s.largestRecv[level], pn, pnLen)
	if fullPN > s.largestRecv[level] {
		s.largestRecv[level] = fullPN
	}

	frames, err := parseFrames(payload)
	if err != nil {
		return
	}
	ackable := false
	for _, f := range frames {
		switch f.typ {
		case frameCrypto:
			ackable = true
			contiguous := s.cryptoIn[level].add(f.crypto.offset, f.crypto.data)
			if len(contiguous) > 0 {
				if err := s.qc.HandleData(level, contiguous); err != nil {
					return
				}
				s.processEvents()
			}
		case frameStream:
			ackable = true
			data := append([]byte(nil), f.stream.data...)
			resp := appendStreamFrame(nil, f.stream.streamID, s.echoOffset, data, false)
			s.echoOffset += uint64(len(data))
			if err := s.sendPacket(tls.QUICEncryptionLevelApplication, resp); err != nil {
			}
			select {
			case s.gotEcho <- data:
			default:
			}
		case frameACK:
			s.handleACK(level, f.ack)
		case frameConnectionClose:
			return
		}
	}
	if ackable {
		if s.recvPNs[level] == nil {
			s.recvPNs[level] = make(map[uint64]bool)
		}
		s.recvPNs[level][fullPN] = true
		s.ackPending[level] = true
	}
}

func (s *testQUICServer) processEvents() {
	for {
		e := s.qc.NextEvent()
		switch e.Kind {
		case tls.QUICNoEvent:
			return
		case tls.QUICSetWriteSecret, tls.QUICSetReadSecret:
			pp, err := newPacketProtection(append([]byte(nil), e.Data...), e.Suite)
			if err != nil {
				continue
			}
			if e.Kind == tls.QUICSetWriteSecret {
				s.encrypt[e.Level] = pp
			} else {
				s.decrypt[e.Level] = pp
			}
		case tls.QUICWriteData:
			out := s.cryptoOut[e.Level]
			off := out.offset
			out.offset += uint64(len(e.Data))
			_ = s.sendCrypto(e.Level, off, e.Data)
		case tls.QUICErrorEvent:
			return
		}
	}
}

func (s *testQUICServer) sendCrypto(level tls.QUICEncryptionLevel, offset uint64, data []byte) error {
	payload := appendCryptoFrame(nil, offset, data)
	return s.sendPacket(level, payload)
}

func (s *testQUICServer) sendPacket(level tls.QUICEncryptionLevel, payload []byte) error {
	pn := s.pn[level]
	s.pn[level]++
	var pp *packetProtection
	var h []byte
	var pnOffset int
	switch level {
	case tls.QUICEncryptionLevelInitial:
		pp = s.initialServerPP
		for {
			h, pnOffset = makeLongHeader(packetTypeInitial, s.clientSCID, s.serverSCID, nil, pn, pnBytes, len(payload))
			total := len(h) + len(payload) + 16
			if total >= minInitialDatagramSize {
				break
			}
			payload = appendPaddingFrames(payload, minInitialDatagramSize-total)
		}
	case tls.QUICEncryptionLevelHandshake:
		pp = s.encrypt[level]
		if pp == nil {
			return io.ErrClosedPipe
		}
		h, pnOffset = makeLongHeader(packetTypeHandshake, s.clientSCID, s.serverSCID, nil, pn, pnBytes, len(payload))
	case tls.QUICEncryptionLevelApplication:
		pp = s.encrypt[level]
		if pp == nil {
			return io.ErrClosedPipe
		}
		h, pnOffset = makeShortHeader(s.clientSCID, pn, pnBytes, 0)
	default:
		return io.ErrClosedPipe
	}
	pkt, err := pp.seal(h, pnOffset, pnBytes, payload, pn)
	if err != nil {
		return err
	}
	_, err = s.conn.WriteToUDP(pkt, s.clientAddr)
	return err
}

func (s *testQUICServer) flushACKs() {
	for level, pending := range s.ackPending {
		if !pending || len(s.recvPNs[level]) == 0 {
			continue
		}
		pns := make([]uint64, 0, len(s.recvPNs[level]))
		for pn := range s.recvPNs[level] {
			pns = append(pns, pn)
		}
		largest, ranges := ackRangesFromPNs(pns)
		payload := appendACKFrame(nil, largest, 0, ranges)
		if s.sendPacket(level, payload) == nil {
			s.ackPending[level] = false
			s.recvPNs[level] = make(map[uint64]bool)
		}
	}
}

func (s *testQUICServer) handleACK(level tls.QUICEncryptionLevel, af *ackFrameData) {
	out := s.cryptoOut[level]
	if out == nil {
		return
	}
	for _, pn := range af.packets {
		delete(out.sent, pn)
	}
}

func (s *testQUICServer) close() {
	s.conn.Close()
	_ = s.qc.Close()
	<-s.done
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestQUICHandshakeAndEcho(t *testing.T) {
	srv, err := startTestQUICServer(t)
	if err != nil {
		t.Fatalf("start test server: %v", err)
	}
	defer srv.close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	stream, err := DialDoQ(ctx, srv.conn.LocalAddr().String(), "localhost", true)
	if err != nil {
		t.Fatalf("DialDoQ: %v", err)
	}
	defer stream.Close()

	msg := []byte("quic-packet-layer-echo")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, msg)
	}

	// Verify DoQ length-prefixed framing via ExchangeDNS.  The echo server
	// returns exactly the bytes we send, so ExchangeDNS must recover them.
	query := minimalDNSQuery()
	resp, err := stream.ExchangeDNS(ctx, query)
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if !bytes.Equal(resp, query) {
		t.Fatalf("DNS echo mismatch: got %d bytes, want %d", len(resp), len(query))
	}
}

func minimalDNSQuery() []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// TestRealDoQ is an optional live interop test against a public DoQ resolver.
// Enable with: DOQ_SERVER=dns.adguard-dns.com:853 go test ./internal/quicproto/ -run TestRealDoQ
func TestRealDoQ(t *testing.T) {
	addr := os.Getenv("DOQ_SERVER")
	if addr == "" {
		t.Skip("set DOQ_SERVER (e.g. dns.adguard-dns.com:853) to run the live test")
	}
	serverName := os.Getenv("DOQ_SERVER_NAME")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := DialDoQ(ctx, addr, serverName, false)
	if err != nil {
		t.Fatalf("DialDoQ(%s): %v", addr, err)
	}
	defer stream.Close()
	resp, err := stream.ExchangeDNS(ctx, minimalDNSQuery())
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("short DNS response: %d bytes", len(resp))
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("unexpected DNS response ID: %x", resp[:2])
	}
	t.Logf("live DoQ response: %d bytes, flags 0x%04x", len(resp), uint16(resp[2])<<8|uint16(resp[3]))
}

// TestVarintRoundTrip checks the varint helpers used throughout the stack.
func TestVarintRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1}
	for _, v := range values {
		b := appendVarint(nil, v)
		got, n, err := readVarint(b)
		if err != nil {
			t.Fatalf("readVarint(%d): %v", v, err)
		}
		if got != v || n != len(b) {
			t.Fatalf("varint round trip: got %d (%d bytes), want %d (%d bytes)", got, n, v, len(b))
		}
	}
}

// TestInitialKeyDerivation checks that deriveInitialKeys produces keys of the
// expected lengths for the AEAD and header protection.
func TestInitialKeyDerivation(t *testing.T) {
	k := deriveInitialKeys([]byte("0123456789abcdef"))
	if len(k.clientKey) != 16 || len(k.clientIV) != 12 || len(k.clientHP) != 16 ||
		len(k.serverKey) != 16 || len(k.serverIV) != 12 || len(k.serverHP) != 16 {
		t.Fatalf("bad initial key lengths: %+v", k)
	}
}
