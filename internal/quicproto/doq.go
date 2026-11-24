package quicproto

// DoQ (DNS over QUIC, RFC 9250) client.  After the QUIC handshake a single
// bidirectional stream (ID 0) carries length-prefixed DNS messages: each
// message is a 2-byte big-endian length followed by the DNS wire-format
// payload.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// streamBuffer is the readable side of a QUIC stream.  QUIC packet processing
// pushes reassembled data into it; the application reads from it with net.Conn
// style deadlines.
type streamBuffer struct {
	mu       sync.Mutex
	buf      []byte
	err      error
	eof      bool
	deadline time.Time
	notify   chan struct{}
}

func newStreamBuffer() *streamBuffer {
	return &streamBuffer{notify: make(chan struct{}, 1)}
}

func (sb *streamBuffer) signal() {
	select {
	case sb.notify <- struct{}{}:
	default:
	}
}

func (sb *streamBuffer) push(data []byte) {
	if len(data) == 0 {
		return
	}
	sb.mu.Lock()
	sb.buf = append(sb.buf, data...)
	sb.mu.Unlock()
	sb.signal()
}

func (sb *streamBuffer) closeWith(err error) {
	sb.mu.Lock()
	if sb.err == nil && !sb.eof {
		if err == nil {
			sb.eof = true
		} else {
			sb.err = err
		}
	}
	sb.mu.Unlock()
	sb.signal()
}

func (sb *streamBuffer) setDeadline(t time.Time) {
	sb.mu.Lock()
	sb.deadline = t
	sb.mu.Unlock()
	sb.signal()
}

func (sb *streamBuffer) read(p []byte, closeCh <-chan struct{}) (int, error) {
	for {
		sb.mu.Lock()
		if len(sb.buf) > 0 {
			n := copy(p, sb.buf)
			sb.buf = sb.buf[n:]
			sb.mu.Unlock()
			return n, nil
		}
		if sb.err != nil {
			err := sb.err
			sb.mu.Unlock()
			return 0, err
		}
		if sb.eof {
			sb.mu.Unlock()
			return 0, io.EOF
		}
		deadline := sb.deadline
		sb.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, osDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}
		select {
		case <-sb.notify:
		case <-timeout:
			if timer != nil {
				timer.Stop()
			}
			return 0, osDeadlineExceeded
		case <-closeCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// osDeadlineExceeded mirrors os.ErrDeadlineExceeded without importing os.
var osDeadlineExceeded = errors.New("i/o timeout")

// getStreamBuffer returns the receive buffer for a stream, creating it on
// first use.  Called with c.mu held (or before any concurrent access).
func (c *quicConnection) getStreamBuffer(streamID uint64) *streamBuffer {
	sb := c.streamBuffers[streamID]
	if sb == nil {
		sb = newStreamBuffer()
		c.streamBuffers[streamID] = sb
	}
	return sb
}

// ---------------------------------------------------------------------------
// QUICStream
// ---------------------------------------------------------------------------

// QUICStream is a bidirectional QUIC stream exposed as a net.Conn.  Writes
// are encoded as STREAM frames at the Application encryption level; reads
// consume reassembled STREAM data from the peer.
type QUICStream struct {
	conn     *quicConnection
	streamID uint64
	readBuf  *streamBuffer

	writeMu      sync.Mutex
	writeOff     uint64
	readDeadline time.Time

	closeOnce sync.Once
}

var _ net.Conn = (*QUICStream)(nil)

func (s *QUICStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	total := 0
	for total < len(p) {
		end := total + 1000
		if end > len(p) {
			end = len(p)
		}
		chunk := p[total:end]
		s.conn.mu.Lock()
		payload := appendStreamFrame(nil, s.streamID, s.writeOff, chunk, false)
		_, err := s.conn.sendPacketLocked(tls.QUICEncryptionLevelApplication, payload)
		s.conn.mu.Unlock()
		if err != nil {
			return total, err
		}
		s.writeOff += uint64(len(chunk))
		total = end
	}
	return total, nil
}

// CloseWrite sends a STREAM frame with the FIN bit set.
func (s *QUICStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	payload := appendStreamFrame(nil, s.streamID, s.writeOff, nil, true)
	_, err := s.conn.sendPacketLocked(tls.QUICEncryptionLevelApplication, payload)
	return err
}

func (s *QUICStream) Read(p []byte) (int, error) {
	return s.readBuf.read(p, s.conn.closeCh)
}

func (s *QUICStream) Close() error {
	var err error
	s.closeOnce.Do(func() {
		_ = s.CloseWrite()
		s.conn.close()
	})
	return err
}

func (s *QUICStream) LocalAddr() net.Addr  { return s.conn.conn.LocalAddr() }
func (s *QUICStream) RemoteAddr() net.Addr { return s.conn.serverAddr }

func (s *QUICStream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *QUICStream) SetReadDeadline(t time.Time) error {
	s.readBuf.setDeadline(t)
	return nil
}

// SetWriteDeadline is accepted for net.Conn compatibility.  QUIC writes are
// non-blocking at this layer and complete in a single datagram, so there is
// no separate write queue to time out.
func (s *QUICStream) SetWriteDeadline(t time.Time) error { return nil }

// ---------------------------------------------------------------------------
// DoQ API
// ---------------------------------------------------------------------------

// DialDoQ opens a DoQ connection: a QUIC connection with ALPN "doq" and a
// bidirectional stream 0.  serverAddr is a UDP address such as
// "dns.adguard-dns.com:853".  serverName is used for TLS SNI and certificate
// verification; when empty it is derived from serverAddr.
func DialDoQ(ctx context.Context, serverAddr, serverName string, skipVerify bool) (*QUICStream, error) {
	if serverName == "" {
		host, _, err := net.SplitHostPort(serverAddr)
		if err != nil {
			return nil, err
		}
		serverName = host
	}
	c, err := dialQUIC(ctx, serverAddr, serverName, "doq", skipVerify)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	sb := c.getStreamBuffer(0)
	c.mu.Unlock()
	return &QUICStream{conn: c, streamID: 0, readBuf: sb}, nil
}

// ExchangeDNS sends one length-prefixed DNS message and reads the response.
func (s *QUICStream) ExchangeDNS(ctx context.Context, wire []byte) ([]byte, error) {
	if len(wire) > 65535 {
		return nil, errors.New("quicproto: DNS message too large for DoQ")
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err := s.Write(frame); err != nil {
		return nil, err
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = s.SetReadDeadline(dl)
	} else {
		_ = s.SetReadDeadline(time.Time{})
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	defer close(done)

	var length [2]byte
	if _, err := io.ReadFull(s, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	resp := make([]byte, n)
	if _, err := io.ReadFull(s, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
