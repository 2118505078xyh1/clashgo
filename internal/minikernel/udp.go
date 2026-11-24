package minikernel

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	udpSessionTimeout = 2 * time.Minute
	maxUDPPacket      = 64 * 1024
)

// decodeSOCKSUDP 解 SOCKS5 UDP 包：RSV(2) FRAG(1) ATYP ADDR PORT DATA。
func decodeSOCKSUDP(b []byte) (*Metadata, []byte, error) {
	if len(b) < 10 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	if b[0] != 0 || b[1] != 0 {
		return nil, nil, &DialError{"bad SOCKS UDP RSV"}
	}
	m, err := readSOCKSAddr(bytes.NewReader(b[3:]))
	if err != nil {
		return nil, nil, err
	}
	// 计算地址部分长度以切出 payload：ATYP(1)+ADDR+PORT(2)。
	off := 3
	switch b[off] {
	case 0x01:
		off += 1 + 4 + 2
	case 0x03:
		off += 1 + 1 + int(b[off+1]) + 2
	case 0x04:
		off += 1 + 16 + 2
	default:
		return nil, nil, &DialError{"bad ATYP"}
	}
	if off > len(b) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return m, b[off:], nil
}

// encodeSOCKSUDP 把远端响应包成 SOCKS5 UDP 格式回给客户端。
func encodeSOCKSUDP(target string, payload []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0, 0, 0}) // RSV + FRAG
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		if len(host) > 255 {
			return nil, &DialError{"host too long"}
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}
	buf.Write([]byte{byte(port >> 8), byte(port)})
	buf.Write(payload)
	return buf.Bytes(), nil
}

// udpSession 是一个 UDP 逻辑会话（按客户端地址复用）。
// Full-Cone 语义：同一客户端地址共享一个出站 socket，且任何远端地址
// 发回的包都能经该 socket 回给客户端。
type udpSession struct {
	metadata *Metadata
	pc       net.PacketConn
	last     time.Time
	writeMu  sync.Mutex
	remotes  map[string]bool // 见过的所有远端地址（Full-Cone 映射）
}

// udpNAT 是 UDP 会话表。
type udpNAT struct {
	mu       sync.Mutex
	sessions map[string]*udpSession
	k        *Kernel
	serverPC net.PacketConn
}

func startUDP(k *Kernel, addr string) (*udpNAT, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	nat := &udpNAT{sessions: map[string]*udpSession{}, k: k, serverPC: pc}
	go nat.serve()
	go nat.cleanupLoop()
	return nat, nil
}

func (n *udpNAT) Close() error {
	n.mu.Lock()
	for _, s := range n.sessions {
		s.pc.Close()
	}
	n.sessions = map[string]*udpSession{}
	n.mu.Unlock()
	return n.serverPC.Close()
}

func (n *udpNAT) serve() {
	buf := make([]byte, maxUDPPacket)
	for {
		nr, client, err := n.serverPC.ReadFrom(buf)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buf[:nr]...)
		go n.handlePacket(client, packet)
	}
}

func (n *udpNAT) handlePacket(client net.Addr, packet []byte) {
	target, payload, err := decodeSOCKSUDP(packet)
	if err != nil {
		return
	}
	target.Network = "udp"
	target.Type = "socks5"
	key := client.String()

	n.mu.Lock()
	s := n.sessions[key]
	if s == nil || time.Since(s.last) > udpSessionTimeout {
		if s != nil {
			s.pc.Close()
		}
		proxy := n.k.selectProxy(target)
		up, ok := proxy.(UDPProxyAdapter)
		if !ok {
			n.mu.Unlock()
			return
		}
		pc, err := up.ListenPacket(context.Background(), target)
		if err != nil {
			n.mu.Unlock()
			return
		}
		s = &udpSession{metadata: target, pc: pc, last: time.Now(), remotes: map[string]bool{}}
		n.sessions[key] = s
		go n.upstreamLoop(client, key, s)
	}
	s.last = time.Now()
	addr, err := resolveUDPAddr(target)
	if err != nil {
		n.mu.Unlock()
		return
	}
	// Full-Cone：记录这个远端地址，回包时用它作为 SOCKS5 源地址。
	s.remotes[addr.String()] = true
	n.mu.Unlock()

	s.writeMu.Lock()
	_, _ = s.pc.WriteTo(payload, addr)
	s.writeMu.Unlock()
}

// upstreamLoop 把出站 UDP 响应包成 SOCKS5 格式回给客户端。
// 用实际响应的远端地址作为源地址（Full-Cone：任何远端都能回包）。
func (n *udpNAT) upstreamLoop(client net.Addr, key string, s *udpSession) {
	buf := make([]byte, maxUDPPacket)
	for {
		nr, remote, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		source := s.metadata.RemoteAddress() // 默认初始目标
		if remote != nil {
			source = remote.String() // Full-Cone：用实际响应源
		}
		reply, err := encodeSOCKSUDP(source, buf[:nr])
		if err != nil {
			continue
		}
		_, _ = n.serverPC.WriteTo(reply, client)
		n.mu.Lock()
		if cur := n.sessions[key]; cur == s {
			s.last = time.Now()
		}
		n.mu.Unlock()
	}
}

func (n *udpNAT) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		n.mu.Lock()
		for key, s := range n.sessions {
			if time.Since(s.last) > udpSessionTimeout {
				s.pc.Close()
				delete(n.sessions, key)
			}
		}
		n.mu.Unlock()
	}
}

func resolveUDPAddr(m *Metadata) (net.Addr, error) {
	if m.ResolvedIP.IsValid() {
		return &net.UDPAddr{IP: m.ResolvedIP.AsSlice(), Port: int(m.DstPort)}, nil
	}
	if m.DstIP.IsValid() {
		return &net.UDPAddr{IP: m.DstIP.AsSlice(), Port: int(m.DstPort)}, nil
	}
	return net.ResolveUDPAddr("udp", m.RemoteAddress())
}
