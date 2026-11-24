// Package ws provides a small, self-contained WebSocket implementation built
// only on the Go standard library. The exported API intentionally mirrors the
// subset of github.com/coder/websocket used by this project so that it can be
// swapped in without touching call sites.
package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"
)

// Message types (opcodes for data frames).
const (
	MessageText   = 1
	MessageBinary = 2
)

// Status codes.
const (
	StatusNormalClosure = 1000
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Frame opcodes.
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// ErrCloseRead is returned by Read after CloseRead has been called.
var ErrCloseRead = errors.New("websocket: CloseRead called on connection")

// CloseError is returned by Read when a close frame is received from the peer.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("websocket: close %d: %s", e.Code, e.Reason)
}

// DialOptions configures Dial. HTTPHeader is copied into the handshake
// request; Host overrides the Host header (useful for VMess style proxies).
// HTTPClient may be supplied to customize TLS or proxy behavior; when nil,
// http.DefaultClient is used.
type DialOptions struct {
	HTTPHeader map[string][]string
	Host       string
	HTTPClient *http.Client
}

// AcceptOptions configures Accept.
type AcceptOptions struct {
	// InsecureSkipVerify disables the default check that the Origin header
	// (when present) matches the request host.
	InsecureSkipVerify bool
}

// Conn represents a WebSocket connection. It is safe for one concurrent
// reader and one or more concurrent writers.
type Conn struct {
	rwc      io.ReadWriteCloser
	br       *bufio.Reader
	isServer bool

	writeMu sync.Mutex
	readMu  sync.Mutex
	stateMu sync.Mutex

	readClosed    bool
	closeOnce     sync.Once
	closeReadOnce sync.Once
	netClosed     chan struct{}
}

func newConn(rwc io.ReadWriteCloser, br *bufio.Reader, isServer bool) *Conn {
	if br == nil {
		br = bufio.NewReader(rwc)
	}
	return &Conn{
		rwc:       rwc,
		br:        br,
		isServer:  isServer,
		netClosed: make(chan struct{}),
	}
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

// Dial performs a WebSocket handshake against url (ws:// or wss://). It
// returns the connection and the HTTP upgrade response.
func Dial(ctx context.Context, url string, opts *DialOptions) (*Conn, *http.Response, error) {
	u, err := neturl.Parse(url)
	if err != nil {
		return nil, nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return nil, nil, fmt.Errorf("websocket: unsupported scheme %q", u.Scheme)
	}

	key, err := makeHandshakeKey()
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	if opts != nil {
		for name, values := range opts.HTTPHeader {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
		if opts.Host != "" {
			req.Host = opts.Host
		}
	}
	// Required handshake headers. Set last so they cannot be overridden.
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Accept-Encoding", "identity")

	client := http.DefaultClient
	if opts != nil && opts.HTTPClient != nil {
		client = opts.HTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, resp, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		return nil, resp, fmt.Errorf("websocket: unexpected HTTP status %d during handshake", resp.StatusCode)
	}
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "websocket") {
		resp.Body.Close()
		return nil, resp, errors.New("websocket: invalid Upgrade header in response")
	}
	if !headerHasToken(resp.Header.Values("Connection"), "upgrade") {
		resp.Body.Close()
		return nil, resp, errors.New("websocket: invalid Connection header in response")
	}
	want := computeAcceptKey(key)
	if !strings.EqualFold(strings.TrimSpace(resp.Header.Get("Sec-WebSocket-Accept")), want) {
		resp.Body.Close()
		return nil, resp, errors.New("websocket: Sec-WebSocket-Accept mismatch")
	}

	// For a protocol switch net/http hands the caller an io.ReadWriteCloser
	// backed by the raw (and possibly TLS) connection.
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return nil, resp, errors.New("websocket: response body is not a readable/writable connection")
	}
	return newConn(rw, nil, false), resp, nil
}

// Accept upgrades an HTTP server request to a WebSocket connection. The
// underlying connection is taken over via http.Hijacker.
func Accept(w http.ResponseWriter, r *http.Request, opts *AcceptOptions) (*Conn, error) {
	if r.Method != http.MethodGet {
		http.Error(w, "websocket: GET required", http.StatusMethodNotAllowed)
		return nil, errors.New("websocket: GET required")
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		http.Error(w, "websocket: invalid Upgrade header", http.StatusBadRequest)
		return nil, errors.New("websocket: invalid Upgrade header")
	}
	if !headerHasToken(r.Header.Values("Connection"), "upgrade") {
		http.Error(w, "websocket: invalid Connection header", http.StatusBadRequest)
		return nil, errors.New("websocket: invalid Connection header")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		w.Header().Set("Sec-WebSocket-Version", "13")
		http.Error(w, "websocket: unsupported version", http.StatusUpgradeRequired)
		return nil, errors.New("websocket: unsupported version")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if !validHandshakeKey(key) {
		http.Error(w, "websocket: invalid Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("websocket: invalid Sec-WebSocket-Key")
	}
	skipOrigin := opts != nil && opts.InsecureSkipVerify
	if !skipOrigin && !validOrigin(r) {
		http.Error(w, "websocket: origin not allowed", http.StatusForbidden)
		return nil, errors.New("websocket: origin not allowed")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket: hijacking not supported", http.StatusInternalServerError)
		return nil, errors.New("websocket: hijacking not supported")
	}
	netConn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	// Write the handshake response through the hijacked buffered writer so
	// no bytes that may already be buffered are lost.
	_, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n"+
		"\r\n", computeAcceptKey(key))
	if err != nil {
		netConn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		netConn.Close()
		return nil, err
	}
	// The handshake response has been flushed, so rw.Writer holds no pending
	// bytes. Write subsequent frames directly to the hijacked connection so
	// they are not left stranded in the (never-flushed again) buffered writer.
	return newConn(struct {
		io.Reader
		io.Writer
		io.Closer
	}{rw.Reader, netConn, netConn}, rw.Reader, true), nil
}

func makeHandshakeKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

func validHandshakeKey(key string) bool {
	if key == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) == 16
}

func computeAcceptKey(key string) string {
	h := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func headerHasToken(values []string, token string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := neturl.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

type frame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func (c *Conn) writeFrame(opcode byte, fin bool, payload []byte) error {
	masked := !c.isServer
	n := len(payload)

	headerLen := 2
	switch {
	case n < 126:
	case n <= 0xffff:
		headerLen += 2
	default:
		headerLen += 8
	}
	if masked {
		headerLen += 4
	}

	buf := make([]byte, headerLen+n)
	first := opcode
	if fin {
		first |= 0x80
	}
	buf[0] = first

	idx := 2
	switch {
	case n < 126:
		buf[1] = byte(n)
	case n <= 0xffff:
		buf[1] = 126
		binary.BigEndian.PutUint16(buf[2:4], uint16(n))
		idx = 4
	default:
		buf[1] = 127
		binary.BigEndian.PutUint64(buf[2:10], uint64(n))
		idx = 10
	}

	if masked {
		buf[1] |= 0x80
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(buf[idx:idx+4], key[:])
		idx += 4
		for i, b := range payload {
			buf[idx+i] = b ^ key[i&3]
		}
	} else {
		copy(buf[idx:], payload)
	}
	return writeAll(c.rwc, buf)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (c *Conn) readFrame() (frame, error) {
	var f frame
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return f, err
	}
	f.fin = hdr[0]&0x80 != 0
	if hdr[0]&0x70 != 0 {
		return f, errors.New("websocket: reserved bits are set")
	}
	f.opcode = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	// A server receives masked frames from clients; a client receives
	// unmasked frames from servers.
	if masked != c.isServer {
		if c.isServer {
			return f, errors.New("websocket: client frame is not masked")
		}
		return f, errors.New("websocket: server frame is masked")
	}

	n := int64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return f, err
		}
		n = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.br, b[:]); err != nil {
			return f, err
		}
		u := binary.BigEndian.Uint64(b[:])
		if u&(1<<63) != 0 || u > uint64(^uint(0)>>1) {
			return f, errors.New("websocket: invalid payload length")
		}
		n = int64(u)
	}
	if f.opcode >= 0x8 && (!f.fin || n > 125) {
		return f, errors.New("websocket: invalid control frame")
	}

	var key [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, key[:]); err != nil {
			return f, err
		}
	}
	payload := make([]byte, int(n))
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return f, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i&3]
		}
	}
	f.payload = payload
	return f, nil
}

// writeControl writes a control frame while holding the write lock.
func (c *Conn) writeControl(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrame(opcode, true, payload)
}

// closeNet closes the underlying transport exactly once.
func (c *Conn) closeNet() {
	c.closeOnce.Do(func() {
		close(c.netClosed)
		_ = c.rwc.Close()
	})
}

// watchCtx arranges for the underlying connection to be closed if ctx is
// cancelled, which unblocks any pending read or write. The returned function
// must be called when the operation completes.
func (c *Conn) watchCtx(ctx context.Context) func() {
	if ctx == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.closeNet()
		case <-done:
		}
	}()
	return func() { close(done) }
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

// ---------------------------------------------------------------------------
// Public message API
// ---------------------------------------------------------------------------

// Write writes a single text (MessageText) or binary (MessageBinary) message.
// Client frames are masked as required by RFC 6455.
func (c *Conn) Write(ctx context.Context, msgType int, data []byte) error {
	if msgType != MessageText && msgType != MessageBinary {
		return fmt.Errorf("websocket: invalid message type %d", msgType)
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := ctxErr(ctx); err != nil {
		return err
	}
	stop := c.watchCtx(ctx)
	defer stop()
	return c.writeFrame(byte(msgType), true, data)
}

// Read reads the next complete message, assembling continuation frames and
// responding to ping frames. Control frames are handled internally.
func (c *Conn) Read(ctx context.Context) (int, []byte, error) {
	c.stateMu.Lock()
	closed := c.readClosed
	c.stateMu.Unlock()
	if closed {
		return 0, nil, ErrCloseRead
	}
	return c.readMessage(ctx)
}

func (c *Conn) readMessage(ctx context.Context) (int, []byte, error) {
	if err := ctxErr(ctx); err != nil {
		return 0, nil, err
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := ctxErr(ctx); err != nil {
		return 0, nil, err
	}
	stop := c.watchCtx(ctx)
	defer stop()

	var msgType int
	var msg []byte
	for {
		f, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch f.opcode {
		case opText, opBinary:
			if msgType != 0 {
				return 0, nil, errors.New("websocket: new data frame during fragmented message")
			}
			if f.fin {
				return int(f.opcode), f.payload, nil
			}
			msgType = int(f.opcode)
			msg = append([]byte(nil), f.payload...)

		case opContinuation:
			if msgType == 0 {
				return 0, nil, errors.New("websocket: unexpected continuation frame")
			}
			msg = append(msg, f.payload...)
			if f.fin {
				typ := msgType
				msgType = 0
				out := msg
				msg = nil
				return typ, out, nil
			}

		case opPing:
			if err := c.writeControl(opPong, f.payload); err != nil {
				return 0, nil, err
			}

		case opPong:
			// Nothing to do.

		case opClose:
			code := StatusNormalClosure
			reason := ""
			if len(f.payload) >= 2 {
				code = int(binary.BigEndian.Uint16(f.payload[:2]))
				reason = string(f.payload[2:])
			}
			// Echo the close code back to the peer before shutting down.
			reply := make([]byte, 2)
			binary.BigEndian.PutUint16(reply, uint16(code))
			_ = c.writeControl(opClose, reply)
			c.closeNet()
			return 0, nil, &CloseError{Code: code, Reason: reason}

		default:
			return 0, nil, fmt.Errorf("websocket: unknown opcode %d", f.opcode)
		}
	}
}

// Close writes a close frame and then closes the underlying connection.
func (c *Conn) Close(code int, reason string) error {
	if code == 0 {
		code = StatusNormalClosure
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], uint16(code))
	copy(payload[2:], reason)
	if len(payload) > 125 {
		payload = payload[:125]
	}
	c.writeMu.Lock()
	err := c.writeFrame(opClose, true, payload)
	c.writeMu.Unlock()
	c.closeNet()
	return err
}

// CloseRead starts a background read loop that answers pings and handles
// close frames. After calling it, Read returns ErrCloseRead. The returned
// context is cancelled when the connection is closed.
func (c *Conn) CloseRead(ctx context.Context) context.Context {
	closeCtx, cancel := context.WithCancel(context.Background())
	c.stateMu.Lock()
	c.readClosed = true
	c.stateMu.Unlock()

	started := false
	c.closeReadOnce.Do(func() {
		started = true
		go func() {
			defer cancel()
			for {
				if _, _, err := c.readMessage(ctx); err != nil {
					return
				}
			}
		}()
	})
	if !started {
		cancel()
	}
	return closeCtx
}

// ---------------------------------------------------------------------------
// net.Conn adapter
// ---------------------------------------------------------------------------

type wsAddr struct {
	network string
	addr    string
}

func (a wsAddr) Network() string { return a.network }
func (a wsAddr) String() string  { return a.addr }

// NetConn wraps c as a net.Conn. Each Write sends one WebSocket message of
// the given type; Read consumes message payloads as a continuous byte stream.
// This is the shape expected by VMess-over-WebSocket transports.
func NetConn(ctx context.Context, c *Conn, msgType int) net.Conn {
	if ctx == nil {
		ctx = context.Background()
	}
	local, remote := net.Addr(wsAddr{"websocket", "websocket"}), net.Addr(wsAddr{"websocket", "websocket"})
	if nc, ok := c.rwc.(net.Conn); ok {
		local, remote = nc.LocalAddr(), nc.RemoteAddr()
	}
	return &wsNetConn{
		ctx:        ctx,
		c:          c,
		msgType:    msgType,
		localAddr:  local,
		remoteAddr: remote,
	}
}

type wsNetConn struct {
	ctx        context.Context
	c          *Conn
	msgType    int
	localAddr  net.Addr
	remoteAddr net.Addr

	mu        sync.Mutex
	remaining []byte
	readErr   error
}

func (n *wsNetConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.readErr != nil {
		return 0, n.readErr
	}
	for len(n.remaining) == 0 {
		_, data, err := n.c.readMessage(n.ctx)
		if err != nil {
			n.readErr = err
			var closeErr *CloseError
			if errors.As(err, &closeErr) || errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, err
		}
		n.remaining = data
	}
	k := copy(p, n.remaining)
	n.remaining = n.remaining[k:]
	return k, nil
}

func (n *wsNetConn) Write(p []byte) (int, error) {
	if err := n.c.Write(n.ctx, n.msgType, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (n *wsNetConn) Close() error {
	return n.c.Close(StatusNormalClosure, "")
}

func (n *wsNetConn) LocalAddr() net.Addr  { return n.localAddr }
func (n *wsNetConn) RemoteAddr() net.Addr { return n.remoteAddr }

func (n *wsNetConn) SetDeadline(t time.Time) error {
	if nc, ok := n.c.rwc.(net.Conn); ok {
		return nc.SetDeadline(t)
	}
	return nil
}

func (n *wsNetConn) SetReadDeadline(t time.Time) error {
	if nc, ok := n.c.rwc.(net.Conn); ok {
		return nc.SetReadDeadline(t)
	}
	return nil
}

func (n *wsNetConn) SetWriteDeadline(t time.Time) error {
	if nc, ok := n.c.rwc.(net.Conn); ok {
		return nc.SetWriteDeadline(t)
	}
	return nil
}
