package minikernel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"clashgo/internal/http3proto"
	"clashgo/internal/quicproto"
)

// hysteria2Real 是基于真 QUIC + HTTP/3 的 Hysteria2 出站。
//
// 协议依据 Hysteria2 源码（core/internal/protocol/）：
//   - 握手：QUIC v1 + TLS 1.3，ALPN "h3"
//   - 认证：HTTP/3 POST https://hysteria/auth，期望状态码 233
//   - TCP 数据面：QUIC Stream 上先发 TCPRequest 帧
//     varint(0x401) + varint(addrLen) + addr + varint(padLen) + padding，
//     再读 TCPResponse 帧 status(1B) + varint(msgLen) + msg + varint(padLen) + padding，
//     随后是原始 TCP 字节流。
//   - UDP 数据面：QUIC DATAGRAM 帧承载 UDPMessage：
//     SessionID(4 BE) + PacketID(2 BE) + FragID(1) + FragCount(1)
//   - varint(addrLen) + addr + data（Hysteria2 自带可靠性层，此处用单分片无重传）。
type hysteria2Real struct {
	name       string
	serverAddr string
	serverName string
	password   string
	skipVerify bool
	ccRX       int

	conn     quicproto.Connection
	authOnce sync.Once
	authErr  error
}

func newHysteria2Real(name, serverAddr, serverName, password string, skipVerify bool, bandwidth int) *hysteria2Real {
	return &hysteria2Real{
		name: name, serverAddr: serverAddr, serverName: serverName,
		password: password, skipVerify: skipVerify, ccRX: bandwidth,
	}
}

func (h *hysteria2Real) Name() string { return h.name }

// ensure 建立 QUIC 连接并完成 HTTP/3 认证（懒启动，sync.Once 并发安全）。
func (h *hysteria2Real) ensure(ctx context.Context) error {
	// 允许测试/调用方直接注入已认证的 conn（跳过握手）。
	if h.conn != nil {
		return nil
	}
	h.authOnce.Do(func() {
		serverName := h.serverName
		if serverName == "" {
			host, _, _ := net.SplitHostPort(h.serverAddr)
			serverName = host
		}
		conn, err := quicproto.Dial(ctx, h.serverAddr, serverName, "h3", h.skipVerify)
		if err != nil {
			h.authErr = fmt.Errorf("hysteria2 QUIC: %w", err)
			return
		}
		ccRX := strconv.Itoa(h.ccRX)
		if h.ccRX <= 0 {
			ccRX = "0"
		}
		resp, err := http3proto.Do(ctx, h3ConnAdapter{conn},
			http3proto.AuthRequest(h.password, ccRX, "", "hysteria"))
		if err != nil {
			conn.Close()
			h.authErr = fmt.Errorf("hysteria2 auth: %w", err)
			return
		}
		if resp.Status != 233 {
			conn.Close()
			h.authErr = fmt.Errorf("hysteria2 auth status %d (want 233)", resp.Status)
			return
		}
		h.conn = conn
	})
	return h.authErr
}

func (h *hysteria2Real) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	if err := h.ensure(ctx); err != nil {
		return nil, err
	}
	addr := m.RemoteAddress()
	if addr == "" {
		return nil, &DialError{"hysteria2: empty destination"}
	}
	stream, err := h.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	// 发 TCPRequest 帧（0x401 + 地址 + 填充）。
	if _, err := stream.Write(buildHyTCPRequest(addr)); err != nil {
		stream.Close()
		return nil, err
	}
	// 读 TCPResponse 帧；服务端拒绝时失败。
	// 注意：不能用 bufio.Reader（会预读后续业务字节导致丢失），必须逐字节读。
	ok, msg, err := readHyTCPResponse(stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("hysteria2 tcp response: %w", err)
	}
	if !ok {
		stream.Close()
		return nil, fmt.Errorf("hysteria2 target %s rejected: %s", addr, msg)
	}
	return stream, nil
}

// ListenPacket 实现 UDPProxyAdapter，用 QUIC DATAGRAM 承载 UDP 报文。
func (h *hysteria2Real) ListenPacket(ctx context.Context, _ *Metadata) (net.PacketConn, error) {
	if err := h.ensure(ctx); err != nil {
		return nil, err
	}
	dc, ok := h.conn.(interface {
		SendDatagram([]byte) error
		ReceiveDatagram(context.Context) ([]byte, error)
	})
	if !ok {
		return nil, errors.New("hysteria2: QUIC DATAGRAM not supported by transport")
	}
	var sid [4]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}
	return &hyPacketConn{
		dc:        dc,
		sessionID: binary.BigEndian.Uint32(sid[:]),
		local:     &net.UDPAddr{IP: net.IPv4zero, Port: 0},
	}, nil
}

// ---------------------------------------------------------------------------
// Hysteria2 协议帧编解码（QUIC varint，RFC 9000 §16）
// ---------------------------------------------------------------------------

const hyFrameTypeTCPRequest = 0x401

func hyAppendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

func hyReadVarint(r io.ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (first >> 6)
	v := uint64(first & 0x3f)
	for i := 1; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// buildHyTCPRequest 构造 TCPRequest 帧：varint(0x401) + varint(addrLen)
// + addr + varint(padLen) + padding。填充内容任意，服务端读后丢弃。
func buildHyTCPRequest(addr string) []byte {
	padding := make([]byte, 64)
	_, _ = rand.Read(padding)
	b := hyAppendVarint(nil, hyFrameTypeTCPRequest)
	b = hyAppendVarint(b, uint64(len(addr)))
	b = append(b, addr...)
	b = hyAppendVarint(b, uint64(len(padding)))
	return append(b, padding...)
}

// oneByteReader 从 io.Reader 逐字节读取，不预读——避免把后续业务数据吞进缓冲区。
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) ReadByte() (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(o.r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// readHyTCPResponse 读 TCPResponse 帧：status(1B) + varint(msgLen)
// + msg + varint(padLen) + padding。
func readHyTCPResponse(r io.Reader) (bool, string, error) {
	obr := oneByteReader{r: r}
	status, err := obr.ReadByte()
	if err != nil {
		return false, "", err
	}
	msgLen, err := hyReadVarint(obr)
	if err != nil {
		return false, "", err
	}
	if msgLen > 2048 {
		return false, "", errors.New("hysteria2: TCPResponse message too long")
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return false, "", err
	}
	padLen, err := hyReadVarint(obr)
	if err != nil {
		return false, "", err
	}
	if padLen > 4096 {
		return false, "", errors.New("hysteria2: TCPResponse padding too long")
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return false, "", err
	}
	return status == 0, string(msg), nil
}

// hyUDPMessage 是 Hysteria2 的 UDP 数据报格式。
type hyUDPMessage struct {
	SessionID uint32
	PacketID  uint16
	FragID    byte
	FragCount byte
	Addr      string
	Data      []byte
}

func (m *hyUDPMessage) serialize() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], m.SessionID)
	binary.BigEndian.PutUint16(b[4:6], m.PacketID)
	b[6], b[7] = m.FragID, m.FragCount
	b = hyAppendVarint(b, uint64(len(m.Addr)))
	b = append(b, m.Addr...)
	return append(b, m.Data...)
}

func parseHyUDPMessage(b []byte) (*hyUDPMessage, error) {
	if len(b) < 9 {
		return nil, errors.New("hysteria2: UDPMessage too short")
	}
	r := &bytesReader{buf: b}
	m := &hyUDPMessage{
		SessionID: binary.BigEndian.Uint32(b[0:4]),
		PacketID:  binary.BigEndian.Uint16(b[4:6]),
		FragID:    b[6],
		FragCount: b[7],
	}
	r.buf = b[8:]
	addrLen, err := hyReadVarint(r)
	if err != nil {
		return nil, err
	}
	if addrLen == 0 || addrLen > 2048 || uint64(len(r.buf)) < addrLen+1 {
		return nil, errors.New("hysteria2: invalid UDPMessage address")
	}
	m.Addr = string(r.buf[:addrLen])
	m.Data = r.buf[addrLen:]
	return m, nil
}

// bytesReader 是 io.ByteReader 的最小实现（避免 import bytes 包之外的依赖）。
type bytesReader struct{ buf []byte }

func (r *bytesReader) ReadByte() (byte, error) {
	if len(r.buf) == 0 {
		return 0, io.EOF
	}
	b := r.buf[0]
	r.buf = r.buf[1:]
	return b, nil
}

// ---------------------------------------------------------------------------
// UDP PacketConn 适配
// ---------------------------------------------------------------------------

type hyPacketConn struct {
	dc interface {
		SendDatagram([]byte) error
		ReceiveDatagram(context.Context) ([]byte, error)
	}
	sessionID uint32
	packetID  atomic.Uint32
	local     net.Addr

	readMu sync.Mutex
	buf    []byte // 未读完的当前数据报
	rem    net.Addr
}

func (c *hyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.buf) == 0 {
		wire, err := c.dc.ReceiveDatagram(context.Background())
		if err != nil {
			return 0, nil, err
		}
		msg, err := parseHyUDPMessage(wire)
		if err != nil {
			return 0, nil, err
		}
		if msg.FragCount != 1 {
			// 多分片需要 Hysteria2 可靠性层重组，当前仅支持单分片。
			return 0, nil, errors.New("hysteria2: fragmented UDP datagram not supported")
		}
		host, portStr, err := net.SplitHostPort(msg.Addr)
		if err != nil {
			return 0, nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0, nil, err
		}
		c.buf = msg.Data
		c.rem = &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, c.rem, nil
}

func (c *hyPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	msg := &hyUDPMessage{
		SessionID: c.sessionID,
		PacketID:  uint16(c.packetID.Add(1)),
		FragID:    0,
		FragCount: 1,
		Addr:      addr.String(),
		Data:      b,
	}
	if err := c.dc.SendDatagram(msg.serialize()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *hyPacketConn) Close() error                     { return nil }
func (c *hyPacketConn) LocalAddr() net.Addr              { return c.local }
func (c *hyPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *hyPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *hyPacketConn) SetWriteDeadline(time.Time) error { return nil }

// ---------------------------------------------------------------------------
// 接口适配
// ---------------------------------------------------------------------------

type h3ConnAdapter struct{ c quicproto.Connection }

func (a h3ConnAdapter) OpenStream() (http3proto.Stream, error) {
	s, err := a.c.OpenStream()
	if err != nil {
		return nil, err
	}
	return h3StreamAdapter{s}, nil
}

func (a h3ConnAdapter) OpenUniStream() (http3proto.Stream, error) {
	s, err := a.c.OpenUniStream()
	if err != nil {
		return nil, err
	}
	return h3StreamAdapter{s}, nil
}

type h3StreamAdapter struct{ quicproto.Stream }

var _ ProxyAdapter = (*hysteria2Real)(nil)
var _ UDPProxyAdapter = (*hysteria2Real)(nil)

// 供单元测试复用的 varint 往返检查辅助。
func hyVarintRoundTrip(v uint64) (uint64, error) {
	return hyReadVarint(&bytesReader{buf: hyAppendVarint(nil, v)})
}
