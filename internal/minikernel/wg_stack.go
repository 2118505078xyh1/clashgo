package minikernel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"clashgo/internal/wgproto"
)

// wgStackConn 在 WireGuard 三层隧道上实现一个简化的 TCP 流连接。
// 通过 WG 隧道发送 IPv4+TCP 包完成握手与数据传输。
type wgStackConn struct {
	tunnel  *wgproto.Tunnel
	srcIP   [4]byte
	dstIP   net.IP
	dstPort uint16
	srcPort uint16

	seq, ack uint32
	closed   bool

	mu     sync.Mutex
	rbuf   []byte
	readCh chan struct{}
	done   chan struct{}
}

func newWGStackConn(t *wgproto.Tunnel, host string, port uint16) *wgStackConn {
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	c := &wgStackConn{
		tunnel: t, srcIP: [4]byte{198, 18, 0, 2},
		dstIP: ip.To4(), dstPort: port, srcPort: 45678,
		seq: 1000, readCh: make(chan struct{}, 1), done: make(chan struct{}),
	}
	go c.recvLoop()
	return c
}

// ipChecksum 计算 IPv4 头校验和。
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i]) << 8
		if i+1 < len(b) {
			sum += uint32(b[i+1])
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (c *wgStackConn) sendTCP(flags byte, payload []byte) error {
	// 简化：直接把 TCP 段通过 WG 隧道发出（省略完整 IP 头的复杂性，
	// 让对端 WG 网关能识别）。实际生产需要完整 IP 封装。
	seg := make([]byte, 20+len(payload))
	seg[0] = byte(c.srcPort >> 8)
	seg[1] = byte(c.srcPort)
	seg[2] = byte(c.dstPort >> 8)
	seg[3] = byte(c.dstPort)
	binary.BigEndian.PutUint32(seg[4:8], c.seq)
	binary.BigEndian.PutUint32(seg[8:12], c.ack)
	seg[12] = 5 << 4 // data offset
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], payload)
	c.seq += uint32(len(payload))
	_, err := c.tunnel.WriteTo(seg, &net.UDPAddr{IP: c.dstIP, Port: int(c.dstPort)})
	return err
}

func (c *wgStackConn) recvLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := c.tunnel.ReadFrom(buf)
		if err != nil {
			close(c.done)
			return
		}
		if n < 20 {
			continue
		}
		dataOffset := int((buf[12] >> 4) * 4)
		if dataOffset < 20 || n < dataOffset {
			continue
		}
		if flags := buf[13]; flags&0x02 != 0 { // SYN-ACK
			c.mu.Lock()
			c.ack = binary.BigEndian.Uint32(buf[4:8]) + 1
			c.seq++
			c.mu.Unlock()
			_ = c.sendTCP(0x10, nil) // ACK
		} else if len(buf[dataOffset:n]) > 0 {
			payload := buf[dataOffset:n]
			c.mu.Lock()
			c.rbuf = append(c.rbuf, payload...)
			c.ack += uint32(len(payload))
			c.mu.Unlock()
			select {
			case c.readCh <- struct{}{}:
			default:
			}
		}
	}
}

func (c *wgStackConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.rbuf) > 0 {
			n := copy(b, c.rbuf)
			c.rbuf = c.rbuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		select {
		case <-c.readCh:
		case <-c.done:
			return 0, io.EOF
		case <-time.After(30 * time.Second):
			return 0, fmt.Errorf("wireguard read timeout")
		}
	}
}

func (c *wgStackConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.sendTCP(0x18, b); err != nil { // PSH+ACK
		return 0, err
	}
	return len(b), nil
}

func (c *wgStackConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		_ = c.sendTCP(0x11, nil) // FIN
	}
	c.mu.Unlock()
	return nil
}

func (c *wgStackConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP(c.srcIP[:]), Port: int(c.srcPort)}
}
func (c *wgStackConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: c.dstIP, Port: int(c.dstPort)} }
func (c *wgStackConn) SetDeadline(t time.Time) error      { return nil }
func (c *wgStackConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wgStackConn) SetWriteDeadline(t time.Time) error { return nil }
