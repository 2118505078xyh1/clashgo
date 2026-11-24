package minikernel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Listener 是 mixed 入站监听器：同一端口自动识别 SOCKS5(0x05) 与 HTTP。
type Listener struct {
	Kernel *Kernel
	ln     net.Listener
	udp    *udpNAT
}

// Start 在 addr 上开始监听 TCP + UDP（异步），返回 Listener 供后续关闭。
func Start(k *Kernel, addr string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	// 用 TCP 实际端口绑定 UDP（端口 0 时两者需一致）。
	tcpAddr := ln.Addr().(*net.TCPAddr)
	udpAddr := net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port))
	udp, err := startUDP(k, udpAddr)
	if err != nil {
		ln.Close()
		return nil, err
	}
	l := &Listener{Kernel: k, ln: ln, udp: udp}
	go l.serve()
	return l, nil
}

// Addr 返回实际监听地址（端口为 0 时用于测试）。
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close 关闭监听器。
func (l *Listener) Close() error {
	if l.udp != nil {
		_ = l.udp.Close()
	}
	return l.ln.Close()
}

func (l *Listener) serve() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.handle(c)
	}
}

// bufferedConn 支持 Peek（分流用），且后续读取仍能拿到完整数据。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (l *Listener) handle(c net.Conn) {
	defer c.Close()
	if l.Kernel.IsPaused() {
		return // 轻量模式挂起：不接收新连接
	}
	bc := &bufferedConn{Conn: c, r: bufio.NewReaderSize(c, 64*1024)}
	head, err := bc.r.Peek(1)
	if err != nil {
		return
	}
	switch head[0] {
	case 0x05: // SOCKS5 版本号
		l.handleSOCKS5(bc)
	case 0x04: // SOCKS4 —— 阶段 1 暂不支持
		return
	default: // HTTP 请求方法首字母
		l.handleHTTP(bc)
	}
}

// handleSOCKS5 完成 RFC1928 握手（方法协商 + CONNECT），构造 Metadata 后交给内核。
func (l *Listener) handleSOCKS5(c *bufferedConn) {
	ctx := context.Background()
	// 方法协商：VER NMETHODS METHODS[]
	var hdr [2]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(c.r, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	// 选择"无需认证"。
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// 请求：VER CMD RSV ATYP ADDR PORT
	var req [3]byte
	if _, err := io.ReadFull(c.r, req[:]); err != nil || req[0] != 0x05 {
		return
	}
	m, err := readSOCKSAddr(c.r)
	if err != nil {
		return
	}
	if req[1] == 0x03 { // UDP ASSOCIATE：TCP 仅保活，UDP 走同端口的 UDP 监听
		addr, ok := c.LocalAddr().(*net.TCPAddr)
		if !ok {
			return
		}
		rep := []byte{0x05, 0x00, 0x00, 0x01}
		rep = append(rep, addr.IP.To4()...)
		port := uint16(addr.Port)
		rep = append(rep, byte(port>>8), byte(port))
		if _, err := c.Write(rep); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c) // 保活直到客户端关闭
		return
	}
	if req[1] != 0x01 { // 仅支持 CONNECT / UDP ASSOCIATE
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// 成功回复：VER REP RSV ATYP BND.ADDR BND.PORT（全 0）。
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	m.Network = "tcp"
	m.Type = "socks5"
	// SOCKS5 客户端已提供明确目标地址（域名或 IP），无需嗅探。
	// 嗅探用于 TUN 等纯 IP 入站（见 tun.go）。
	_ = l.Kernel.Dispatch(ctx, c, m)
}

// readSOCKSAddr 解析 SOCKS5 的目标地址（ATYP + ADDR + PORT）。
func readSOCKSAddr(r io.Reader) (*Metadata, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return nil, err
	}
	m := &Metadata{}
	switch atyp[0] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		m.DstIP, _ = netip.AddrFromSlice(ip[:])
	case 0x03: // 域名
		var ln [1]byte
		if _, err := io.ReadFull(r, ln[:]); err != nil {
			return nil, err
		}
		b := make([]byte, int(ln[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		m.Host = string(b)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		m.DstIP, _ = netip.AddrFromSlice(ip[:])
	default:
		return nil, fmt.Errorf("unsupported ATYP %d", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, err
	}
	m.DstPort = uint16(port[0])<<8 | uint16(port[1])
	return m, nil
}

// handleHTTP 处理 HTTP 代理请求：CONNECT 走隧道，普通 HTTP 重新序列化请求后转发。
func (l *Listener) handleHTTP(c *bufferedConn) {
	ctx := context.Background()
	req, err := http.ReadRequest(c.r)
	if err != nil {
		return
	}
	host, port := hostPortFromRequest(req)
	if host == "" {
		return
	}
	m := &Metadata{
		Host:    host,
		DstPort: uint16(port),
		Network: "tcp",
	}

	if req.Method == http.MethodConnect {
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		m.Type = "https"
		_ = l.Kernel.Dispatch(ctx, c, m)
		return
	}

	// 普通 HTTP：先选路拨号，再把请求写进隧道（复用标准库的序列化）。
	m.Type = "http"
	remote, err := l.Kernel.route(ctx, m)
	if err != nil {
		return
	}
	defer remote.Close()
	defer c.Close()
	if err := req.Write(remote); err != nil {
		return
	}
	relay(c, remote)
}

// hostPortFromRequest 从 HTTP 请求中解析目标主机与端口（含 origin-form 的 Host 头）。
func hostPortFromRequest(req *http.Request) (string, int) {
	host := req.URL.Hostname()
	portStr := req.URL.Port()
	if host == "" {
		h := req.Host
		// 处理 host:port（IPv6 的 [...] 形式不含裸冒号分割）。
		if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i+1:], "]") {
			host, portStr = h[:i], h[i+1:]
		} else {
			host = h
		}
	}
	port := 80
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return host, port
}
