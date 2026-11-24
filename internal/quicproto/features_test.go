package quicproto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"clashgo/internal/http3proto"
)

// featureServer is an extended local QUIC echo server used to exercise the
// features added on top of the basic packet stack: DATAGRAM, ChaCha20, Retry,
// version negotiation, application ACKs (congestion control) and key update.

type featureOpts struct {
	suites       []uint16
	sendRetry    bool
	sendVN       bool
	ackApp       bool
	echoDatagram bool
	// h3Response makes stream frames receive a real HTTP/3 HEADERS response
	// instead of echoing the request bytes back to the client.
	h3Response bool
}

type featureServer struct {
	conn       *net.UDPConn
	qc         *tls.QUICConn
	clientAddr *net.UDPAddr
	opts       featureOpts

	clientDCID []byte // original destination CID of the first Initial
	clientSCID []byte
	serverSCID []byte

	initialClientPP *packetProtection
	initialServerPP *packetProtection

	encrypt     map[tls.QUICEncryptionLevel]*packetProtection
	decrypt     map[tls.QUICEncryptionLevel]*packetProtection
	cryptoIn    map[tls.QUICEncryptionLevel]*cryptoBuffer
	cryptoOut   map[tls.QUICEncryptionLevel]*cryptoOutState
	pn          map[tls.QUICEncryptionLevel]uint64
	largestRecv map[tls.QUICEncryptionLevel]uint64
	recvPNs     map[tls.QUICEncryptionLevel]map[uint64]bool
	ackPending  map[tls.QUICEncryptionLevel]bool

	echoOffsets map[uint64]uint64 // 每条流独立的 echo offset
	echoCh      chan []byte
	dgCh        chan []byte

	localKeyPhase  byte
	peerKeyPhase   byte
	prevDecryptApp *packetProtection

	firstInitialSeen bool
	done             chan struct{}
}

func startFeatureServer(t *testing.T, opts featureOpts) (*featureServer, error) {
	t.Helper()
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
		CipherSuites: opts.suites,
	}})
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	s := &featureServer{
		conn:        conn,
		qc:          qc,
		opts:        opts,
		serverSCID:  serverSCID,
		encrypt:     map[tls.QUICEncryptionLevel]*packetProtection{},
		decrypt:     map[tls.QUICEncryptionLevel]*packetProtection{},
		cryptoIn:    map[tls.QUICEncryptionLevel]*cryptoBuffer{},
		cryptoOut:   map[tls.QUICEncryptionLevel]*cryptoOutState{},
		pn:          map[tls.QUICEncryptionLevel]uint64{},
		largestRecv: map[tls.QUICEncryptionLevel]uint64{},
		recvPNs:     map[tls.QUICEncryptionLevel]map[uint64]bool{},
		ackPending:  map[tls.QUICEncryptionLevel]bool{},
		echoCh:      make(chan []byte, 256),
		echoOffsets: make(map[uint64]uint64),
		dgCh:        make(chan []byte, 64),
		done:        make(chan struct{}),
	}
	for _, level := range []tls.QUICEncryptionLevel{
		tls.QUICEncryptionLevelInitial, tls.QUICEncryptionLevelHandshake, tls.QUICEncryptionLevelApplication,
	} {
		s.cryptoIn[level] = &cryptoBuffer{}
		s.cryptoOut[level] = &cryptoOutState{sent: map[uint64][]cryptoChunk{}}
	}
	qc.SetTransportParameters(encodeServerTransportParameters(serverSCID, nil))
	if err := qc.Start(context.Background()); err != nil {
		conn.Close()
		return nil, err
	}
	go s.serve()
	return s, nil
}

func (s *featureServer) serve() {
	defer close(s.done)
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.clientAddr = addr
		s.handleDatagram(buf[:n])
	}
}

func (s *featureServer) handleDatagram(datagram []byte) {
	defer s.flushACKs()
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
}

func (s *featureServer) processPacket(pkt []byte, info packetHeaderInfo) {
	var level tls.QUICEncryptionLevel
	var pnOffset int
	if info.isLong {
		switch info.typ {
		case packetTypeInitial:
			if !s.firstInitialSeen {
				s.firstInitialSeen = true
				s.clientDCID = append([]byte(nil), info.dcid...)
				s.clientSCID = append([]byte(nil), info.scid...)
				ik := deriveInitialKeys(s.clientDCID)
				var err error
				s.initialClientPP, err = newPacketProtectionFromRaw(ik.clientKey, ik.clientIV, ik.clientHP)
				if err != nil {
					return
				}
				s.initialServerPP, err = newPacketProtectionFromRaw(ik.serverKey, ik.serverIV, ik.serverHP)
				if err != nil {
					return
				}
				if s.opts.sendRetry {
					_ = s.sendRetryPacket()
					return // do not feed this Initial to TLS
				}
				if s.opts.sendVN {
					_ = s.sendVersionNegotiation()
					return
				}
			}
			level = tls.QUICEncryptionLevelInitial
		case packetTypeHandshake:
			level = tls.QUICEncryptionLevelHandshake
		default:
			return
		}
		pnOffset = info.pnOffset
	} else {
		level = tls.QUICEncryptionLevelApplication
		pnOffset = 1 + len(s.clientSCID)
	}

	var fullPN uint64
	var payload []byte
	var err error
	if info.isLong {
		pp := s.initialClientPP
		if level == tls.QUICEncryptionLevelHandshake {
			pp = s.decrypt[level]
		}
		if pp == nil {
			return
		}
		fullPN, _, _, payload, err = pp.openFull(pkt, pnOffset, true, s.largestRecv[level])
	} else {
		fullPN, _, _, payload, err = s.openApplication(pkt, pnOffset)
	}
	if err != nil {
		return
	}
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
			off := s.echoOffsets[f.stream.streamID]
			respData := data
			if s.opts.h3Response && len(data) > 0 {
				respData = h3ResponseFrame()
			}
			resp := appendStreamFrame(nil, f.stream.streamID, off, respData, false)
			s.echoOffsets[f.stream.streamID] = off + uint64(len(respData))
			_ = s.sendPacket(tls.QUICEncryptionLevelApplication, resp)
			select {
			case s.echoCh <- data:
			default:
			}
		case frameACK:
			s.handleACK(level, f.ack)
		case frameDatagram:
			if s.opts.echoDatagram {
				_ = s.sendPacket(tls.QUICEncryptionLevelApplication, appendDatagramFrame(nil, f.datagram))
			}
			select {
			case s.dgCh <- append([]byte(nil), f.datagram...):
			default:
			}
		case frameConnectionClose:
			return
		}
	}
	if ackable && (level != tls.QUICEncryptionLevelApplication || s.opts.ackApp) {
		if s.recvPNs[level] == nil {
			s.recvPNs[level] = map[uint64]bool{}
		}
		s.recvPNs[level][fullPN] = true
		s.ackPending[level] = true
	}
}

// openApplication detects client key-phase flips and keeps both read and write
// keys in sync, mirroring the client's InitiateKeyUpdate behaviour.
func (s *featureServer) openApplication(pkt []byte, pnOffset int) (fullPN uint64, pnLen int, header, payload []byte, err error) {
	cur := s.decrypt[tls.QUICEncryptionLevelApplication]
	if cur == nil {
		return 0, 0, nil, nil, io.ErrClosedPipe
	}
	phase := byte(0)
	if mask, mErr := cur.hpMask(pkt, pnOffset); mErr == nil {
		phase = (pkt[0] ^ (mask[0] & 0x1f)) & keyPhaseBit
	}
	if phase != s.peerKeyPhase {
		next, nerr := cur.update()
		if nerr != nil {
			return 0, 0, nil, nil, nerr
		}
		s.prevDecryptApp = cur
		s.decrypt[tls.QUICEncryptionLevelApplication] = next
		if s.encrypt[tls.QUICEncryptionLevelApplication] != nil {
			if nextW, werr := s.encrypt[tls.QUICEncryptionLevelApplication].update(); werr == nil {
				s.encrypt[tls.QUICEncryptionLevelApplication] = nextW
			}
		}
		s.peerKeyPhase = phase
		s.localKeyPhase ^= 1
	}
	return cur.openFull(pkt, pnOffset, false, s.largestRecv[tls.QUICEncryptionLevelApplication])
}

func (s *featureServer) processEvents() {
	for {
		e := s.qc.NextEvent()
		switch e.Kind {
		case tls.QUICNoEvent:
			return
		case tls.QUICSetWriteSecret, tls.QUICSetReadSecret:
			suite := e.Suite
			if len(s.opts.suites) == 1 {
				suite = s.opts.suites[0]
			}
			pp, err := newPacketProtection(append([]byte(nil), e.Data...), suite)
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
			payload := appendCryptoFrame(nil, off, e.Data)
			_ = s.sendPacket(e.Level, payload)
		case tls.QUICErrorEvent:
			return
		}
	}
}

func (s *featureServer) sendPacket(level tls.QUICEncryptionLevel, payload []byte) error {
	pn := s.pn[level]
	s.pn[level]++
	var pp *packetProtection
	var h []byte
	var pnOffset int
	switch level {
	case tls.QUICEncryptionLevelInitial:
		pp = s.initialServerPP
		if pp == nil {
			return io.ErrClosedPipe
		}
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
		h, pnOffset = makeShortHeader(s.clientSCID, pn, pnBytes, s.localKeyPhase)
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

func (s *featureServer) flushACKs() {
	for level, pending := range s.ackPending {
		if !pending || len(s.recvPNs[level]) == 0 {
			continue
		}
		pns := make([]uint64, 0, len(s.recvPNs[level]))
		for pn := range s.recvPNs[level] {
			pns = append(pns, pn)
		}
		largest, ranges := ackRangesFromPNs(pns)
		if s.sendPacket(level, appendACKFrame(nil, largest, 0, ranges)) == nil {
			s.ackPending[level] = false
			s.recvPNs[level] = map[uint64]bool{}
		}
	}
}

func (s *featureServer) handleACK(level tls.QUICEncryptionLevel, af *ackFrameData) {
	out := s.cryptoOut[level]
	if out == nil {
		return
	}
	for _, pn := range af.packets {
		delete(out.sent, pn)
	}
}

func (s *featureServer) sendRetryPacket() error {
	scid, err := randomBytes(8)
	if err != nil {
		return err
	}
	token := []byte("retry-token-1234")
	h := []byte{packetTypeRetry}
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], quicVersion1)
	h = append(h, ver[:]...)
	h = appendVarint(h, uint64(len(s.clientSCID)))
	h = append(h, s.clientSCID...)
	h = appendVarint(h, uint64(len(scid)))
	h = append(h, scid...)
	h = append(h, token...)

	aad := make([]byte, 0, 1+len(s.clientDCID)+len(h))
	aad = append(aad, byte(len(s.clientDCID)))
	aad = append(aad, s.clientDCID...)
	aad = append(aad, h...)
	key := []byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e}
	nonce := []byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	pkt := gcm.Seal(append([]byte(nil), h...), nonce, nil, aad)
	_, err = s.conn.WriteToUDP(pkt, s.clientAddr)
	return err
}

func (s *featureServer) sendVersionNegotiation() error {
	vnscid, err := randomBytes(8)
	if err != nil {
		return err
	}
	pkt := []byte{0x80} // header form = 1, fixed bit = 0
	var zero, v1 [4]byte
	binary.BigEndian.PutUint32(zero[:], 0)
	binary.BigEndian.PutUint32(v1[:], quicVersion1)
	pkt = append(pkt, zero[:]...)
	pkt = appendVarint(pkt, uint64(len(s.clientSCID)))
	pkt = append(pkt, s.clientSCID...)
	pkt = appendVarint(pkt, uint64(len(vnscid)))
	pkt = append(pkt, vnscid...)
	pkt = append(pkt, v1[:]...)
	_, err = s.conn.WriteToUDP(pkt, s.clientAddr)
	return err
}

// h3ResponseFrame builds a minimal HTTP/3 HEADERS frame carrying :status 200.
// The QUIC layer only needs to deliver these bytes; QPACK encoding is done by
// http3proto so the test exercises both real QUIC streams and real H3 frames.
func h3ResponseFrame() []byte {
	payload := http3proto.EncodeFieldSection([]http3proto.HeaderField{
		{Name: ":status", Value: "200"},
	})
	b := appendVarint(nil, http3proto.FrameHeaders)
	b = appendVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func (s *featureServer) close() {
	s.conn.Close()
	_ = s.qc.Close()
	<-s.done
}

// dialFeature connects the local stack to a featureServer using an optional
// cipher suite restriction.
func dialFeature(t *testing.T, s *featureServer, suites []uint16) *quicConnection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := dialQUICWithSuites(ctx, s.conn.LocalAddr().String(), "localhost", "doq", true, suites)
	if err != nil {
		t.Fatalf("dialQUICWithSuites: %v", err)
	}
	return c
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDatagramSendReceive(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{echoDatagram: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	// The Connection interface must expose the DATAGRAM API.
	var conn Connection = c
	payload := []byte("unreliable-datagram-payload")
	if err := conn.SendDatagram(payload); err != nil {
		t.Fatalf("SendDatagram: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := conn.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("ReceiveDatagram: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("datagram mismatch: got %q, want %q", got, payload)
	}

	// Cancelled context must unblock a waiting reader.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := conn.ReceiveDatagram(ctx2); err != context.Canceled {
		t.Fatalf("cancelled ReceiveDatagram: got %v, want context.Canceled", err)
	}
}

func TestDatagramBeforeHandshakeFails(t *testing.T) {
	c := &quicConnection{}
	if err := c.SendDatagram([]byte("x")); err == nil {
		t.Fatal("SendDatagram before handshake should fail")
	}
}

func TestChaCha20HandshakeAndEcho(t *testing.T) {
	suite := []uint16{tls.TLS_CHACHA20_POLY1305_SHA256}
	srv, err := startFeatureServer(t, featureOpts{suites: suite})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, suite)
	defer c.Close()

	stream, err := c.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("chacha20-quic-echo")
	if _, err := stream.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
	appPP := c.encrypt[tls.QUICEncryptionLevelApplication]
	t.Logf("negotiated suite = 0x%04x, hpChaCha = %v", appPP.suite, appPP.hpChaCha)
	if appPP.suite != tls.TLS_CHACHA20_POLY1305_SHA256 || !appPP.hpChaCha {
		t.Fatal("ChaCha20 suite was not negotiated")
	}
}

func TestLargeTransferCongestionControl(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{ackApp: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	stream, err := c.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("QUIC-100KB-"), 10000) // 110,000 bytes
	done := make(chan error, 1)
	go func() {
		_, err := stream.Write(payload)
		done <- err
	}()
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(payload))))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large transfer mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	c.mu.Lock()
	rttUsed, srtt := c.rttSampleUsed, c.smoothedRTT
	c.mu.Unlock()
	if rttUsed && srtt <= 0 {
		t.Fatal("RTT estimator was not updated")
	}
}

func TestKeyUpdateRoundTrip(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{ackApp: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	stream, err := c.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	echo := func(msg []byte) {
		t.Helper()
		if _, err := stream.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, msg) {
			t.Fatalf("echo mismatch after key update: %q", buf)
		}
	}

	echo([]byte("before-key-update"))
	oldKey := c.encrypt[tls.QUICEncryptionLevelApplication]
	if err := c.InitiateKeyUpdate(); err != nil {
		t.Fatalf("InitiateKeyUpdate: %v", err)
	}
	newKey := c.encrypt[tls.QUICEncryptionLevelApplication]
	if newKey == oldKey || c.localKeyPhase == 0 {
		t.Fatal("key update did not rotate keys / flip Key Phase")
	}
	echo([]byte("after-key-update"))
}

func TestRetryHandshake(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{sendRetry: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	if len(c.retryToken) == 0 || len(c.serverSCID) == 0 {
		t.Fatal("Retry token / SCID was not installed")
	}
	stream, err := c.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("after-retry")
	if _, err := stream.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestVersionNegotiationHandshake(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{sendVN: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	if !c.versionConfirmed {
		t.Fatal("version was not confirmed after negotiation")
	}
	stream, err := c.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("after-version-negotiation")
	if _, err := stream.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestExportKeyingMaterial(t *testing.T) {
	srv, err := startFeatureServer(t, featureOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()
	c := dialFeature(t, srv, nil)
	defer c.Close()

	// The Connection interface must expose the EKM exporter.
	var conn Connection = c
	label, ctxBytes := "5918201A-7E2B-4A6E-9A0D-000000000001", []byte("password")
	ekm, err := conn.ExportKeyingMaterial(label, ctxBytes, 32)
	if err != nil {
		t.Fatalf("ExportKeyingMaterial: %v", err)
	}
	if len(ekm) != 32 {
		t.Fatalf("EKM length = %d, want 32", len(ekm))
	}
	again, err := conn.ExportKeyingMaterial(label, ctxBytes, 32)
	if err != nil || !bytes.Equal(ekm, again) {
		t.Fatalf("EKM not deterministic: %v / %v", ekm, again)
	}
	// EKM is direction-independent: the server must derive the same value.
	cs := srv.qc.ConnectionState()
	want, err := cs.ExportKeyingMaterial(label, ctxBytes, 32)
	if err != nil {
		t.Fatalf("server ExportKeyingMaterial: %v", err)
	}
	if !bytes.Equal(ekm, want) {
		t.Fatalf("client/server EKM mismatch:\nclient %x\nserver %x", ekm, want)
	}
}
