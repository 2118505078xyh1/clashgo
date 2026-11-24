package minikernel

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
)

// ---- 最小 SS 测试服务器（仅用于验证自研 SS 出站的正确性）----

func ssMasterKey(password []byte, size int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < size {
		h.Write(prev)
		h.Write(password)
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:size]
}

func ssSubkey(key, salt []byte, size int) []byte {
	// 标准库 HKDF-SHA1（RFC 5869）。
	mac := hmac.New(sha1.New, salt)
	mac.Write(key)
	prk := mac.Sum(nil)
	out := make([]byte, 0, size)
	var t []byte
	for i := byte(1); len(out) < size; i++ {
		mac = hmac.New(sha1.New, prk)
		mac.Write(t)
		mac.Write([]byte("ss-subkey"))
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:size]
}

func ssIncNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func ssWritePacket(w io.Writer, aead cipher.AEAD, nonce []byte, data []byte) error {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(data)))
	if _, err := w.Write(aead.Seal(nil, nonce, l[:], nil)); err != nil {
		return err
	}
	ssIncNonce(nonce)
	_, err := w.Write(aead.Seal(nil, nonce, data, nil))
	ssIncNonce(nonce)
	return err
}

func ssReadPacket(r io.Reader, aead cipher.AEAD, nonce []byte) ([]byte, error) {
	encLen := make([]byte, 18)
	if _, err := io.ReadFull(r, encLen); err != nil {
		return nil, err
	}
	lenPt, err := aead.Open(nil, nonce, encLen, nil)
	if err != nil {
		return nil, err
	}
	ssIncNonce(nonce)
	enc := make([]byte, int(binary.BigEndian.Uint16(lenPt))+16)
	if _, err := io.ReadFull(r, enc); err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, err
	}
	ssIncNonce(nonce)
	return pt, nil
}

func parseSSAddr(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, fmt.Errorf("short addr")
	}
	var host string
	var i int
	switch b[0] {
	case 1:
		if len(b) < 1+4+2 {
			return "", nil, fmt.Errorf("short ipv4")
		}
		host = net.IP(b[1:5]).String()
		i = 5
	case 3:
		n := int(b[1])
		if len(b) < 2+n+2 {
			return "", nil, fmt.Errorf("short domain")
		}
		host = string(b[2 : 2+n])
		i = 2 + n
	case 4:
		if len(b) < 1+16+2 {
			return "", nil, fmt.Errorf("short ipv6")
		}
		host = net.IP(b[1:17]).String()
		i = 17
	default:
		return "", nil, fmt.Errorf("bad atyp %d", b[0])
	}
	port := int(b[i])<<8 | int(b[i+1])
	return net.JoinHostPort(host, strconv.Itoa(port)), b[i+2:], nil
}

// startSSServer 启动一个 aes-256-gcm 的 SS 服务端，返回其地址。
func startSSServer(t *testing.T, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	master := ssMasterKey([]byte(password), 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSSConn(c, master)
		}
	}()
	return ln.Addr().String()
}

func handleSSConn(c net.Conn, master []byte) {
	defer c.Close()
	// 读客户端 salt。
	salt := make([]byte, 32)
	if _, err := io.ReadFull(c, salt); err != nil {
		return
	}
	block, _ := aes.NewCipher(ssSubkey(master, salt, 32))
	aead, _ := cipher.NewGCM(block)
	reqNonce := make([]byte, 12)
	first, err := ssReadPacket(c, aead, reqNonce)
	if err != nil {
		return
	}
	target, early, err := parseSSAddr(first)
	if err != nil {
		return
	}
	remote, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer remote.Close()
	if len(early) > 0 {
		remote.Write(early)
	}

	// 服务端 salt + 响应密钥。
	respSalt := make([]byte, 32)
	for i := range respSalt {
		respSalt[i] = byte(i * 7)
	}
	c.Write(respSalt)
	rblock, _ := aes.NewCipher(ssSubkey(master, respSalt, 32))
	respAead, _ := cipher.NewGCM(rblock)
	respNonce := make([]byte, 12)

	// 远端 → 客户端（加密）。
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := remote.Read(buf)
			if n > 0 {
				if ssWritePacket(c, respAead, respNonce, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	// 客户端 → 远端（解密）。
	buf := make([]byte, 32*1024)
	for {
		pkt, err := ssReadPacket(c, aead, reqNonce)
		if err != nil {
			return
		}
		if len(pkt) > 0 {
			if _, err := remote.Write(pkt); err != nil {
				return
			}
		}
		_ = buf
	}
}

// ---- 端到端测试 ----

func TestSSOutboundEndToEnd(t *testing.T) {
	const password = "test-password"
	echo := startEcho(t)
	ssAddr := startSSServer(t, password)

	k := NewKernel()
	ss, err := NewShadowSocks("MYSS", ssAddr, "aes-256-gcm", password)
	if err != nil {
		t.Fatal(err)
	}
	k.Proxies["MYSS"] = ss
	k.AddRules([]string{"MATCH,,MYSS"}) // 全部流量走 SS

	l, err := Start(k, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// SOCKS5 握手 → CONNECT 到 echo（流量经 SS 出站）。
	c.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	io.ReadFull(c, reply)
	host, portStr, _ := net.SplitHostPort(echo)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host).To4()
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("connect reply = %v, %v", rep, err)
	}

	msg := []byte("hello-via-ss")
	c.Write(msg)
	r := bufio.NewReader(c)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
	waitStats(t, k)
	_ = context.Background()
}
