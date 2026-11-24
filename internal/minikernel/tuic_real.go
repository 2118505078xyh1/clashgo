package minikernel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"clashgo/internal/quicproto"
)

// tuicReal 是按 TUIC v5 协议实现的出站（参考 sing-quic/tuic 源码）。
//
// 协议要点：
//   - QUIC v1 + TLS 1.3；连接复用
//   - 认证：OpenUniStream 写 [5][0x00][UUID 16][EKM 32]
//     EKM = TLS-Exporter(label=UUID 字符串, context=password, length=32)
//   - TCP：OpenStream 首包写 [5][0x01][Address][data]，之后原始字节流
//   - UDP：QUIC DATAGRAM 写 [5][0x02][SessionID 2][Address][data]
//   - 心跳：DATAGRAM [5][0x04]
//
// Address 序列化：1 字节类型 + 地址 + 2 字节端口（大端）
//
//	0x00 = FQDN（1 字节长度 + 域名），0x01 = IPv4(4)，0x02 = IPv6(16)
type tuicReal struct {
	name       string
	serverAddr string
	serverName string
	uuid       string
	password   string
	skipVerify bool

	conn       quicproto.Connection
	sessionSeq atomic.Uint32
	authOnce   sync.Once
	authErr    error
}

func newTUICReal(name, serverAddr, uuid, password, serverName string, skipVerify bool) *tuicReal {
	return &tuicReal{
		name: name, serverAddr: serverAddr, serverName: serverName,
		uuid: uuid, password: password, skipVerify: skipVerify,
	}
}

func (t *tuicReal) Name() string { return t.name }

func (t *tuicReal) ensure(ctx context.Context) error {
	t.authOnce.Do(func() {
		serverName := t.serverName
		if serverName == "" {
			host, _, _ := net.SplitHostPort(t.serverAddr)
			serverName = host
		}
		conn, err := quicproto.Dial(ctx, t.serverAddr, serverName, "h3", t.skipVerify)
		if err != nil {
			t.authErr = fmt.Errorf("tuic QUIC: %w", err)
			return
		}
		// 认证：EKM(label=UUID, context=password, 32)
		ekmProvider, ok := conn.(interface {
			ExportKeyingMaterial(string, []byte, int) ([]byte, error)
		})
		if !ok {
			conn.Close()
			t.authErr = errors.New("tuic: QUIC transport does not support EKM")
			return
		}
		uuidBytes, err := parseTUICUUID(t.uuid)
		if err != nil {
			conn.Close()
			t.authErr = err
			return
		}
		// TUIC v5 规定 label 是 16 字节 UUID 的原始字节串（非带连字符文本），
		// context 是密码，长度 32（见 sing-quic/tuic/client.go）。
		token, err := ekmProvider.ExportKeyingMaterial(string(uuidBytes[:]), []byte(t.password), 32)
		if err != nil {
			conn.Close()
			t.authErr = fmt.Errorf("tuic EKM: %w", err)
			return
		}
		authStream, err := conn.OpenUniStream()
		if err != nil {
			conn.Close()
			t.authErr = err
			return
		}
		authReq := make([]byte, 0, 2+16+32)
		authReq = append(authReq, 5, 0) // Version, CommandAuthenticate
		authReq = append(authReq, uuidBytes[:]...)
		authReq = append(authReq, token...)
		if _, err := authStream.Write(authReq); err != nil {
			conn.Close()
			t.authErr = fmt.Errorf("tuic auth write: %w", err)
			return
		}
		_ = authStream.Close()
		t.conn = conn
	})
	if t.authErr != nil {
		return t.authErr
	}
	if t.conn == nil {
		return errors.New("tuic: not connected")
	}
	return nil
}

func (t *tuicReal) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	if err := t.ensure(ctx); err != nil {
		return nil, err
	}
	addr := m.RemoteAddress()
	if addr == "" {
		return nil, &DialError{"tuic: empty destination"}
	}
	stream, err := t.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	wc := &tuicStreamConn{Stream: stream, dest: addr}
	return wc, nil
}

func (t *tuicReal) ListenPacket(ctx context.Context, _ *Metadata) (net.PacketConn, error) {
	if err := t.ensure(ctx); err != nil {
		return nil, err
	}
	dc, ok := t.conn.(interface {
		SendDatagram([]byte) error
		ReceiveDatagram(context.Context) ([]byte, error)
	})
	if !ok {
		return nil, errors.New("tuic: QUIC DATAGRAM not supported by transport")
	}
	var sid [2]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	pc := &tuicPacketConn{
		dc:        dc,
		sessionID: binary.BigEndian.Uint16(sid[:]),
		local:     &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		done:      make(chan struct{}),
	}
	// 后台心跳（TUIC 默认 10s）。
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = dc.SendDatagram([]byte{5, 4}) // Version, CommandHeartbeat
			case <-pc.done:
				return
			}
		}
	}()
	return pc, nil
}

// ---------------------------------------------------------------------------
// TUIC 协议编解码
// ---------------------------------------------------------------------------

const (
	tuicVersion         byte = 5
	tuicCmdAuthenticate byte = 0
	tuicCmdConnect      byte = 1
	tuicCmdPacket       byte = 2
	tuicCmdHeartbeat    byte = 4
)

func parseTUICUUID(s string) ([16]byte, error) {
	var out [16]byte
	cleaned := ""
	for _, c := range s {
		if c != '-' && c != '{' && c != '}' {
			cleaned += string(c)
		}
	}
	if len(cleaned) != 32 {
		return out, fmt.Errorf("tuic: invalid UUID %q: want 32 hex digits", s)
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return out, fmt.Errorf("tuic: invalid UUID %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

// tuicSerializeAddr 序列化目标地址：type(1) + addr + port(2 BE)。
func tuicSerializeAddr(host string, port uint16) ([]byte, error) {
	var b []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 0x01)
			b = append(b, v4...)
		} else {
			b = append(b, 0x02)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("tuic: invalid host %q", host)
		}
		b = append(b, 0x00, byte(len(host)))
		b = append(b, host...)
	}
	b = append(b, byte(port>>8), byte(port))
	return b, nil
}

func tuicParseAddr(b []byte) (string, uint16, error) {
	if len(b) < 4 {
		return "", 0, errors.New("tuic: short address")
	}
	typ := b[0]
	b = b[1:]
	var host string
	switch typ {
	case 0x00:
		if len(b) < 1+2 {
			return "", 0, errors.New("tuic: short FQDN address")
		}
		l := int(b[0])
		if len(b) < 1+l+2 {
			return "", 0, errors.New("tuic: truncated FQDN")
		}
		host = string(b[1 : 1+l])
		b = b[1+l:]
	case 0x01:
		if len(b) < 4+2 {
			return "", 0, errors.New("tuic: short IPv4 address")
		}
		host = net.IP(b[:4]).String()
		b = b[4:]
	case 0x02:
		if len(b) < 16+2 {
			return "", 0, errors.New("tuic: short IPv6 address")
		}
		host = net.IP(b[:16]).String()
		b = b[16:]
	default:
		return "", 0, fmt.Errorf("tuic: unknown address type 0x%02x", typ)
	}
	port := binary.BigEndian.Uint16(b[:2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), port, nil
}

// ---------------------------------------------------------------------------
// TCP stream 包装（首包携带 Connect 请求）
// ---------------------------------------------------------------------------

type tuicStreamConn struct {
	quicproto.Stream
	dest    string
	mu      sync.Mutex
	written bool
}

func (c *tuicStreamConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.written {
		addr, err := tuicSerializeAddr(splitHostPort(c.dest))
		if err != nil {
			return 0, err
		}
		req := make([]byte, 0, 2+len(addr)+len(b))
		req = append(req, tuicVersion, tuicCmdConnect)
		req = append(req, addr...)
		req = append(req, b...)
		if _, err := c.Stream.Write(req); err != nil {
			return 0, err
		}
		c.written = true
		return len(b), nil
	}
	return c.Stream.Write(b)
}

func splitHostPort(addr string) (string, uint16) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, uint16(p)
}

// ---------------------------------------------------------------------------
// UDP PacketConn 适配
// ---------------------------------------------------------------------------

type tuicPacketConn struct {
	dc interface {
		SendDatagram([]byte) error
		ReceiveDatagram(context.Context) ([]byte, error)
	}
	sessionID uint16
	packetID  atomic.Uint32
	local     net.Addr
	done      chan struct{}

	readMu sync.Mutex
	buf    []byte
	rem    net.Addr
}

func (c *tuicPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.buf) == 0 {
		wire, err := c.dc.ReceiveDatagram(context.Background())
		if err != nil {
			return 0, nil, err
		}
		// 报文格式：[Version][Cmd][SessionID 2][PacketID 2][FragTotal 1]
		// [FragID 1][DataLen 2][Address][Data]（见 sing-quic/tuic/packet.go）
		if len(wire) < 10 || wire[0] != tuicVersion || wire[1] != tuicCmdPacket {
			return 0, nil, errors.New("tuic: unexpected datagram")
		}
		fragTotal := wire[6]
		fragID := wire[7]
		if fragTotal != 1 || fragID != 0 {
			return 0, nil, errors.New("tuic: fragmented UDP datagram not supported")
		}
		addr, _, err := tuicParseAddr(wire[10:])
		if err != nil {
			return 0, nil, err
		}
		consumed := tuicAddrLen(wire[10:])
		c.buf = wire[10+consumed:]
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return 0, nil, err
		}
		port, _ := strconv.Atoi(portStr)
		c.rem = &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, c.rem, nil
}

func tuicAddrLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	switch b[0] {
	case 0x00:
		if len(b) < 2 {
			return 0
		}
		return 1 + 1 + int(b[1]) + 2
	case 0x01:
		return 1 + 4 + 2
	case 0x02:
		return 1 + 16 + 2
	}
	return 0
}

func (c *tuicPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	ab, err := tuicSerializeAddr(host, uint16(port))
	if err != nil {
		return 0, err
	}
	wire := make([]byte, 0, 10+len(ab)+len(b))
	wire = append(wire, tuicVersion, tuicCmdPacket)
	wire = append(wire, byte(c.sessionID>>8), byte(c.sessionID))
	pid := uint16(c.packetID.Add(1))
	wire = append(wire, byte(pid>>8), byte(pid))
	wire = append(wire, 1, 0) // fragmentTotal=1, fragmentID=0
	wire = append(wire, byte(len(b)>>8), byte(len(b)))
	wire = append(wire, ab...)
	wire = append(wire, b...)
	if err := c.dc.SendDatagram(wire); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *tuicPacketConn) Close() error                     { close(c.done); return nil }
func (c *tuicPacketConn) LocalAddr() net.Addr              { return c.local }
func (c *tuicPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *tuicPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tuicPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ ProxyAdapter = (*tuicReal)(nil)
var _ UDPProxyAdapter = (*tuicReal)(nil)
