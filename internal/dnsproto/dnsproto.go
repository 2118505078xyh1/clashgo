// Package dnsproto 是一个仅依赖 Go 标准库的 DNS 报文编解码库。
//
// 它提供 DNS 消息的 Pack/Unpack（支持 RFC 1035 域名压缩指针 0xC0）、
// UDP/TCP 服务器以及 UDP 客户端，可作为 github.com/miekg/dns 的轻量替代。
//
// 注意：Data 字段保存 RDATA 的线格式字节。Unpack 会把常见的「名字型」
// RDATA（CNAME/NS/PTR/DNAME/MX/SOA/SRV）中的压缩名字展开成未压缩的线格式，
// 以保证把该 Msg 再次 Pack 时 RDATA 内的偏移指针不会失效；A/AAAA/TXT 等
// 其他类型的 RDATA 原样保留。
package dnsproto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// 常用 TYPE / CLASS 常量。
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeDNAME uint16 = 39

	ClassINET uint16 = 1
)

// RCODE 常量。
const (
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// 解析错误。
var (
	ErrShortHeader   = errors.New("dnsproto: short DNS header")
	ErrMalformedName = errors.New("dnsproto: malformed domain name")
	ErrNameTooLong   = errors.New("dnsproto: domain name too long")
	ErrCompression   = errors.New("dnsproto: bad compression pointer")
	ErrMessageTooBig = errors.New("dnsproto: message too large")
)

// Msg 是一条 DNS 消息。
type Msg struct {
	ID       uint16
	Response bool
	Opcode   int
	RD       bool // Recursion Desired
	RA       bool // Recursion Available
	Rcode    int
	Question []Question
	Answer   []RR
}

// Question 是问题段中的一条记录。
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

// RR 是资源记录。Data 为 RDATA 的原始线格式字节。
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

// A 是 A 记录的便利类型（嵌入 RR，可直接取 a.RR 放进 Msg.Answer）。
type A struct {
	RR
	IP net.IP
}

// AAAA 是 AAAA 记录的便利类型。
type AAAA struct {
	RR
	IP net.IP
}

// Fqdn 确保域名以点结尾；空串与 "." 都返回根域名 "."。
func Fqdn(s string) string {
	if s == "" || s == "." {
		return "."
	}
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// SetQuestion 把 m 重置为一条查询报文：随机 ID、RD=1、单条问题记录。
func (m *Msg) SetQuestion(name string, qtype uint16) {
	m.ID = newID()
	m.Response = false
	m.Opcode = 0
	m.RD = true
	m.RA = false
	m.Rcode = RcodeSuccess
	m.Question = []Question{{Name: Fqdn(name), Qtype: qtype, Qclass: ClassINET}}
	m.Answer = nil
}

// SetReply 根据请求构造响应报文（ Echo ID / Opcode / RD，复制问题段）。
func (m *Msg) SetReply(req *Msg) {
	m.ID = req.ID
	m.Response = true
	m.Opcode = req.Opcode
	m.RD = req.RD
	m.RA = false
	m.Rcode = RcodeSuccess
	m.Question = append([]Question(nil), req.Question...)
	m.Answer = nil
}

func newID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}
	return uint16(time.Now().UnixNano())
}

// ---------------------------------------------------------------- 域名编解码

// packName 把域名写入 buf。comp 为「域名后缀 -> 首次出现偏移」的压缩表。
// 写入时优先使用压缩指针（0xC0 | offset），因此编码出的报文与 RFC 1035 兼容。
func packName(buf *bytes.Buffer, name string, comp map[string]uint16) error {
	if name == "" || name == "." {
		buf.WriteByte(0)
		return nil
	}
	if name[len(name)-1] != '.' {
		name += "."
	}
	// 线格式长度 = 每个标签 1 字节长度 + 标签内容 + 结尾 0 = len(name)+1。
	if len(name)+1 > 255 {
		return fmt.Errorf("%w: %q", ErrNameTooLong, name)
	}
	base := buf.Len()
	for i := 0; i < len(name); {
		suffix := name[i:]
		if off, ok := comp[suffix]; ok && off <= 0x3FFF {
			buf.WriteByte(byte(0xC0 | (off >> 8)))
			buf.WriteByte(byte(off))
			return nil
		}
		j := strings.IndexByte(name[i:], '.')
		if j < 0 {
			return fmt.Errorf("%w: %q", ErrMalformedName, name)
		}
		if j == 0 {
			return fmt.Errorf("%w: empty label in %q", ErrMalformedName, name)
		}
		if j > 63 {
			return fmt.Errorf("%w: label > 63 bytes in %q", ErrMalformedName, name)
		}
		label := name[i : i+j]
		if off := base + i; off <= 0x3FFF {
			comp[suffix] = uint16(off)
		}
		buf.WriteByte(byte(j))
		buf.WriteString(label)
		i += j + 1
	}
	buf.WriteByte(0)
	return nil
}

// unpackName 从 msg[off] 读取域名，支持 0xC0 压缩指针。
// 返回 (FQDN, 该域名在原始报文中的结束偏移, error)。
func unpackName(msg []byte, off int) (string, int, error) {
	if off < 0 || off >= len(msg) {
		return "", 0, fmt.Errorf("%w: offset %d", ErrCompression, off)
	}
	var labels []string
	wireLen := 1
	p := off
	end := -1
	hops := 0
	for {
		hops++
		if hops > 256 {
			return "", 0, fmt.Errorf("%w: pointer loop at %d", ErrCompression, off)
		}
		if p >= len(msg) {
			return "", 0, io.ErrUnexpectedEOF
		}
		c := msg[p]
		switch c & 0xC0 {
		case 0x00: // 普通标签
			if c == 0 {
				p++
				if end < 0 {
					end = p
				}
				if len(labels) == 0 {
					return ".", end, nil
				}
				return strings.Join(labels, ".") + ".", end, nil
			}
			l := int(c)
			if p+1+l > len(msg) {
				return "", 0, io.ErrUnexpectedEOF
			}
			wireLen += 1 + l
			if wireLen > 255 {
				return "", 0, ErrNameTooLong
			}
			labels = append(labels, string(msg[p+1:p+1+l]))
			p += 1 + l
		case 0xC0: // 压缩指针
			if p+1 >= len(msg) {
				return "", 0, io.ErrUnexpectedEOF
			}
			ptr := int(uint16(c&0x3F)<<8) | int(msg[p+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("%w: %d out of range", ErrCompression, ptr)
			}
			if end < 0 {
				end = p + 2
			}
			p = ptr
		default: // 0x40 / 0x80 保留
			return "", 0, fmt.Errorf("%w: reserved label type 0x%02x", ErrMalformedName, c)
		}
	}
}

// PackName 把 FQDN 编码为未压缩的线格式字节（用于自行构造 RDATA）。
func PackName(name string) ([]byte, error) {
	var buf bytes.Buffer
	if err := packName(&buf, name, nil); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnpackName 从线格式字节的 off 处解码域名，支持压缩指针。
func UnpackName(b []byte, off int) (string, int, error) { return unpackName(b, off) }

// appendNameWire 把 FQDN 以未压缩线格式追加到 dst。
func appendNameWire(dst []byte, name string) []byte {
	if name == "" || name == "." {
		return append(dst, 0)
	}
	if name[len(name)-1] != '.' {
		name += "."
	}
	for i := 0; i < len(name); {
		j := strings.IndexByte(name[i:], '.')
		if j < 0 {
			break
		}
		if j == 0 {
			i++
			continue
		}
		label := name[i : i+j]
		for len(label) > 63 {
			dst = append(dst, 63)
			dst = append(dst, label[:63]...)
			label = label[63:]
		}
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
		i += j + 1
	}
	return append(dst, 0)
}

// normalizeRDATA 展开名字型 RDATA 中的压缩指针。解码失败时退回原样字节。
func normalizeRDATA(msg []byte, start, rdlen int, typ uint16) []byte {
	raw := append([]byte(nil), msg[start:start+rdlen]...)
	decodedName := func(off int) ([]byte, int, bool) {
		n, next, err := unpackName(msg, off)
		if err != nil || next > start+rdlen {
			return nil, 0, false
		}
		return appendNameWire(nil, n), next, true
	}
	switch typ {
	case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
		if w, _, ok := decodedName(start); ok {
			return w
		}
	case TypeMX:
		if rdlen >= 3 {
			if w, _, ok := decodedName(start + 2); ok {
				return append(append([]byte(nil), msg[start:start+2]...), w...)
			}
		}
	case TypeSRV:
		if rdlen >= 7 {
			if w, _, ok := decodedName(start + 6); ok {
				return append(append([]byte(nil), msg[start:start+6]...), w...)
			}
		}
	case TypeSOA:
		w1, next, ok := decodedName(start)
		if !ok {
			break
		}
		w2, next2, ok := decodedName(next)
		if !ok || next2+20 > start+rdlen {
			break
		}
		out := append(w1, w2...)
		return append(out, msg[next2:next2+20]...)
	}
	return raw
}

// ---------------------------------------------------------------- 消息编解码

// Pack 把 Msg 序列化为 DNS 线格式报文。
func Pack(m *Msg) ([]byte, error) {
	if len(m.Question) > 0xFFFF || len(m.Answer) > 0xFFFF {
		return nil, ErrMessageTooBig
	}
	var buf bytes.Buffer
	buf.Write(make([]byte, 12)) // 先占位，最后回填头部

	comp := make(map[string]uint16)
	for _, q := range m.Question {
		if err := packName(&buf, q.Name, comp); err != nil {
			return nil, err
		}
		put16(&buf, q.Qtype)
		put16(&buf, q.Qclass)
	}
	for _, rr := range m.Answer {
		if err := packName(&buf, rr.Name, comp); err != nil {
			return nil, err
		}
		put16(&buf, rr.Type)
		put16(&buf, rr.Class)
		put32(&buf, rr.TTL)
		if len(rr.Data) > 0xFFFF {
			return nil, ErrMessageTooBig
		}
		put16(&buf, uint16(len(rr.Data)))
		buf.Write(rr.Data)
	}

	var flags uint16
	if m.Response {
		flags |= 0x8000
	}
	flags |= uint16(m.Opcode&0x0F) << 11
	if m.RD {
		flags |= 0x0100
	}
	if m.RA {
		flags |= 0x0080
	}
	flags |= uint16(m.Rcode & 0x0F)

	b := buf.Bytes()
	binary.BigEndian.PutUint16(b[0:2], m.ID)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(m.Question)))
	binary.BigEndian.PutUint16(b[6:8], uint16(len(m.Answer)))
	binary.BigEndian.PutUint16(b[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(b[10:12], 0) // ARCOUNT
	return b, nil
}

func put16(buf *bytes.Buffer, v uint16) {
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
}

func put32(buf *bytes.Buffer, v uint32) {
	buf.WriteByte(byte(v >> 24))
	buf.WriteByte(byte(v >> 16))
	buf.WriteByte(byte(v >> 8))
	buf.WriteByte(byte(v))
}

// Unpack 解析 DNS 线格式报文；NS/AR 段会被正确跳过（按 RDLENGTH）。
func Unpack(b []byte) (*Msg, error) {
	if len(b) < 12 {
		return nil, ErrShortHeader
	}
	m := &Msg{}
	m.ID = binary.BigEndian.Uint16(b[0:2])
	flags := binary.BigEndian.Uint16(b[2:4])
	m.Response = flags&0x8000 != 0
	m.Opcode = int((flags >> 11) & 0x0F)
	m.RD = flags&0x0100 != 0
	m.RA = flags&0x0080 != 0
	m.Rcode = int(flags & 0x0F)
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))

	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := unpackName(b, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+4 > len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		m.Question = append(m.Question, Question{
			Name:   name,
			Qtype:  binary.BigEndian.Uint16(b[off : off+2]),
			Qclass: binary.BigEndian.Uint16(b[off+2 : off+4]),
		})
		off += 4
	}

	for i := 0; i < an+ns+ar; i++ {
		name, n, err := unpackName(b, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+10 > len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		class := binary.BigEndian.Uint16(b[off+2 : off+4])
		ttl := binary.BigEndian.Uint32(b[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			return nil, io.ErrUnexpectedEOF
		}
		if i < an {
			m.Answer = append(m.Answer, RR{
				Name:  name,
				Type:  typ,
				Class: class,
				TTL:   ttl,
				Data:  normalizeRDATA(b, off, rdlen, typ),
			})
		}
		off += rdlen
	}
	return m, nil
}

// ---------------------------------------------------------------- 便捷构造

// NewA 构造一条 A 记录；IP 非法时 Data 为 nil。
func NewA(name string, ttl uint32, ip net.IP) *A {
	var data []byte
	if v4 := ip.To4(); v4 != nil {
		data = append([]byte(nil), v4...)
	}
	return &A{RR: RR{Name: Fqdn(name), Type: TypeA, Class: ClassINET, TTL: ttl, Data: data}, IP: ip}
}

// NewAAAA 构造一条 AAAA 记录；IP 非法时 Data 为 nil。
func NewAAAA(name string, ttl uint32, ip net.IP) *AAAA {
	var data []byte
	if v16 := ip.To16(); v16 != nil {
		data = append([]byte(nil), v16...)
	}
	return &AAAA{RR: RR{Name: Fqdn(name), Type: TypeAAAA, Class: ClassINET, TTL: ttl, Data: data}, IP: ip}
}

// NewCNAME 构造一条 CNAME 记录（目标名字以未压缩线格式写入 RDATA）。
func NewCNAME(name, target string, ttl uint32) RR {
	return RR{
		Name:  Fqdn(name),
		Type:  TypeCNAME,
		Class: ClassINET,
		TTL:   ttl,
		Data:  appendNameWire(nil, Fqdn(target)),
	}
}

// AddA 追加一条 A 记录（IP 非法则忽略）。
func (m *Msg) AddA(name string, ttl uint32, ip net.IP) {
	if rr := NewA(name, ttl, ip); len(rr.RR.Data) == net.IPv4len {
		m.Answer = append(m.Answer, rr.RR)
	}
}

// AddAAAA 追加一条 AAAA 记录（IP 非法则忽略）。
func (m *Msg) AddAAAA(name string, ttl uint32, ip net.IP) {
	if rr := NewAAAA(name, ttl, ip); len(rr.RR.Data) == net.IPv6len {
		m.Answer = append(m.Answer, rr.RR)
	}
}

// AddCNAME 追加一条 CNAME 记录。
func (m *Msg) AddCNAME(name, target string, ttl uint32) {
	m.Answer = append(m.Answer, NewCNAME(name, target, ttl))
}

// ParseA 从 RR.Data 解析 IPv4 地址。
func ParseA(rr RR) (net.IP, error) {
	if len(rr.Data) != net.IPv4len {
		return nil, fmt.Errorf("dnsproto: A RDATA length = %d, want 4", len(rr.Data))
	}
	return net.IPv4(rr.Data[0], rr.Data[1], rr.Data[2], rr.Data[3]), nil
}

// ParseAAAA 从 RR.Data 解析 IPv6 地址。
func ParseAAAA(rr RR) (net.IP, error) {
	if len(rr.Data) != net.IPv6len {
		return nil, fmt.Errorf("dnsproto: AAAA RDATA length = %d, want 16", len(rr.Data))
	}
	return net.IP(append([]byte(nil), rr.Data...)), nil
}

// AnswerIPs 提取回答段中所有 A/AAAA 记录的 IP。
func (m *Msg) AnswerIPs() []net.IP {
	var out []net.IP
	for _, rr := range m.Answer {
		switch rr.Type {
		case TypeA:
			if ip, err := ParseA(rr); err == nil {
				out = append(out, ip)
			}
		case TypeAAAA:
			if ip, err := ParseAAAA(rr); err == nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- 服务器

// Handler 处理 DNS 请求。
type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
}

// HandlerFunc 把函数适配为 Handler。
type HandlerFunc func(w ResponseWriter, r *Msg)

func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) { f(w, r) }

// ResponseWriter 用于写回 DNS 响应。
type ResponseWriter interface {
	WriteMsg(*Msg) error
}

// Server 是 DNS 服务器。Net 可为 udp/udp4/udp6/tcp/tcp4/tcp6，默认 udp。
type Server struct {
	Addr    string
	Net     string
	Handler Handler

	mu     sync.Mutex
	pc     net.PacketConn
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

type responseWriter struct {
	conn net.Conn
	pc   net.PacketConn
	addr net.Addr
}

func (w *responseWriter) WriteMsg(m *Msg) error {
	b, err := Pack(m)
	if err != nil {
		return err
	}
	if w.pc != nil {
		_, err = w.pc.WriteTo(b, w.addr)
		return err
	}
	if w.conn == nil {
		return errors.New("dnsproto: no underlying connection")
	}
	if len(b) > 0xFFFF {
		return ErrMessageTooBig
	}
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(b)))
	if err := writeAll(w.conn, head[:]); err != nil {
		return err
	}
	return writeAll(w.conn, b)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ListenAndServe 监听并处理请求，直到 Shutdown 或发生致命错误。
func (s *Server) ListenAndServe() error {
	network := s.Net
	if network == "" {
		network = "udp"
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("dnsproto: server is closed")
	}
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.mu.Unlock()

	switch network {
	case "udp", "udp4", "udp6":
		pc, err := net.ListenPacket(network, s.Addr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = pc.Close()
			return errors.New("dnsproto: server is closed")
		}
		s.pc = pc
		s.mu.Unlock()
		defer pc.Close()
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if s.isClosed() {
					return nil
				}
				return err
			}
			req, err := Unpack(buf[:n])
			if err != nil {
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(&responseWriter{pc: pc, addr: addr}, req)
			}()
		}

	case "tcp", "tcp4", "tcp6":
		ln, err := net.Listen(network, s.Addr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = ln.Close()
			return errors.New("dnsproto: server is closed")
		}
		s.ln = ln
		s.mu.Unlock()
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if s.isClosed() {
					return nil
				}
				return err
			}
			s.mu.Lock()
			s.conns[conn] = struct{}{}
			s.mu.Unlock()
			s.wg.Add(1)
			go s.serveConn(conn)
		}

	default:
		return fmt.Errorf("dnsproto: unsupported network %q", network)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	var head [2]byte
	for {
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			return
		}
		l := int(binary.BigEndian.Uint16(head[:]))
		if l == 0 {
			return
		}
		payload := make([]byte, l)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		req, err := Unpack(payload)
		if err != nil {
			return
		}
		s.serve(&responseWriter{conn: conn}, req)
	}
}

func (s *Server) serve(w ResponseWriter, req *Msg) {
	h := s.Handler
	if h == nil {
		h = HandlerFunc(func(w ResponseWriter, r *Msg) {
			m := &Msg{}
			m.SetReply(r)
			m.Rcode = RcodeServerFailure
			_ = w.WriteMsg(m)
		})
	}
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				m := &Msg{}
				m.SetReply(req)
				m.Rcode = RcodeServerFailure
				_ = w.WriteMsg(m)
			}
		}()
		h.ServeDNS(w, req)
	}()
}

// Shutdown 关闭监听 socket 与所有活动连接，并等待处理中的请求结束。
func (s *Server) Shutdown() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	pc, ln := s.pc, s.ln
	s.pc, s.ln = nil, nil
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.mu.Unlock()

	var errs []error
	if pc != nil {
		if err := pc.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if ln != nil {
		if err := ln.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.wg.Wait()
	return errors.Join(errs...)
}

// ---------------------------------------------------------------- 客户端

// Client 是 UDP DNS 客户端。Timeout<=0 时只受 ctx 控制（无超时）。
type Client struct {
	Timeout time.Duration
}

// Exchange 使用 context.Background 发起一次查询。
func (c *Client) Exchange(m *Msg, server string) (*Msg, time.Duration, error) {
	return c.ExchangeContext(context.Background(), m, server)
}

// ExchangeContext 通过 UDP 向 server（形如 "223.5.5.5:53"，省略端口时用 53）
// 发送 m，并返回响应、往返耗时与错误。ctx 取消会中断阻塞的读操作。
func (c *Client) ExchangeContext(ctx context.Context, m *Msg, server string) (*Msg, time.Duration, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, time.Since(start), err
	}
	b, err := Pack(m)
	if err != nil {
		return nil, time.Since(start), err
	}

	d := net.Dialer{}
	if c.Timeout > 0 {
		d.Timeout = c.Timeout
	}
	conn, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return nil, time.Since(start), err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	deadline := time.Time{}
	if c.Timeout > 0 {
		deadline = start.Add(c.Timeout)
	}
	if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(b); err != nil {
		return nil, time.Since(start), err
	}

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, time.Since(start), err
		}
		resp, err := Unpack(buf[:n])
		if err != nil || resp.ID != m.ID {
			continue // 忽略畸形报文与 ID 不匹配的报文
		}
		return resp, time.Since(start), nil
	}
}
