package ssproto

// SS AEAD UDP 数据包格式（SIP022）：
//
//	salt(keyLen 字节) || Seal(nonce=0, 2 字节长度) || Seal(nonce=1, addr+payload)
//
// 其中 addr 为 SOCKS5 ATYP+ADDR+PORT，每个包使用独立随机 salt，
// 因此 nonce 每次从 0 开始。底层 conn 已连接到 SS 服务端。

import (
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"sync"
)

var _ net.PacketConn = (*udpConn)(nil)

// udpConn 实现 net.PacketConn，对上层暴露明文 UDP 语义。
type udpConn struct {
	*net.UDPConn // 继承 Close / LocalAddr / Deadline 等方法
	method       *Method
	readMu       sync.Mutex
	writeMu      sync.Mutex
}

// ListenPacket 基于已连接到 SS 服务端的 UDPConn 创建加密的 PacketConn。
func (m *Method) ListenPacket(conn *net.UDPConn) (*udpConn, error) {
	if conn == nil {
		return nil, errors.New("ssproto: nil UDP connection")
	}
	return &udpConn{UDPConn: conn, method: m}, nil
}

// WriteTo 把 payload 加密后发往 SS 服务端，目标地址写在加密头中。
// addr 为明文目标地址（host:port）。
func (c *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, port, err := splitTargetAddr(addr)
	if err != nil {
		return 0, err
	}
	salt := make([]byte, c.method.keyLen)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	aead, err := c.method.subkey(salt)
	if err != nil {
		return 0, err
	}
	addrBytes := encodeAddr(host, port)
	plain := make([]byte, 0, len(addrBytes)+len(b))
	plain = append(plain, addrBytes...)
	plain = append(plain, b...)

	var lenBuf [2]byte
	lenBuf[0] = byte(len(plain) >> 8)
	lenBuf[1] = byte(len(plain))
	nonce := make([]byte, aead.NonceSize())
	sealedLen := aead.Seal(nil, nonce, lenBuf[:], nil)
	incNonce(nonce)
	sealedData := aead.Seal(nil, nonce, plain, nil)

	packet := make([]byte, 0, len(salt)+len(sealedLen)+len(sealedData))
	packet = append(packet, salt...)
	packet = append(packet, sealedLen...)
	packet = append(packet, sealedData...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.UDPConn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom 从 SS 服务端读取一个加密包，解密后返回明文 payload 与真实源地址。
func (c *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	buf := make([]byte, 65535)
	n, err := c.UDPConn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	packet := buf[:n]
	saltLen := c.method.keyLen
	if len(packet) < saltLen+2+16 {
		return 0, nil, errors.New("ssproto: udp packet too short")
	}
	salt := packet[:saltLen]
	aead, err := c.method.subkey(salt)
	if err != nil {
		return 0, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	lenPT, err := aead.Open(nil, nonce, packet[saltLen:saltLen+2+16], nil)
	if err != nil {
		return 0, nil, err
	}
	incNonce(nonce)
	ptLen := int(lenPT[0])<<8 | int(lenPT[1])
	bodyStart := saltLen + 2 + 16
	if len(packet)-bodyStart < ptLen+16 {
		return 0, nil, errors.New("ssproto: udp packet truncated")
	}
	pt, err := aead.Open(nil, nonce, packet[bodyStart:bodyStart+ptLen+16], nil)
	if err != nil {
		return 0, nil, err
	}
	host, port, off, err := parseSocksAddr(pt)
	if err != nil {
		return 0, nil, err
	}
	payload := pt[off:]
	n = copy(b, payload)
	return n, newPacketAddr(host, port), nil
}

// splitTargetAddr 从 net.Addr 中提取 host 和 port。
func splitTargetAddr(addr net.Addr) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(p), nil
}

// parseSocksAddr 解析 SOCKS5 ATYP+ADDR+PORT，返回 host、port 和 payload 起始偏移。
func parseSocksAddr(b []byte) (host string, port uint16, offset int, err error) {
	if len(b) == 0 {
		return "", 0, 0, errors.New("ssproto: empty addr")
	}
	switch b[0] {
	case 1: // IPv4
		if len(b) < 1+4+2 {
			return "", 0, 0, errors.New("ssproto: bad ipv4 addr")
		}
		host = net.IP(b[1:5]).String()
		offset = 1 + 4
	case 3: // 域名
		if len(b) < 2 {
			return "", 0, 0, errors.New("ssproto: bad domain addr")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, 0, errors.New("ssproto: bad domain addr")
		}
		host = string(b[2 : 2+l])
		offset = 2 + l
	case 4: // IPv6
		if len(b) < 1+16+2 {
			return "", 0, 0, errors.New("ssproto: bad ipv6 addr")
		}
		host = net.IP(b[1:17]).String()
		offset = 1 + 16
	default:
		return "", 0, 0, errors.New("ssproto: unknown addr type")
	}
	port = uint16(b[offset])<<8 | uint16(b[offset+1])
	return host, port, offset + 2, nil
}

// packetAddr 用于域名目标（无法用 *net.UDPAddr 表示）。
type packetAddr struct {
	network string
	address string
}

func (a *packetAddr) Network() string { return a.network }
func (a *packetAddr) String() string  { return a.address }

func newPacketAddr(host string, port uint16) net.Addr {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(port)}
	}
	return &packetAddr{network: "udp", address: net.JoinHostPort(host, strconv.Itoa(int(port)))}
}
