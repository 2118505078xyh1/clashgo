package minikernel

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startTrojanServer 是一个最小 Trojan 服务端（明文，仅测试用）。
func startTrojanServer(t *testing.T, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				pw, err := r.ReadString('\n')
				if err != nil || strings.TrimSpace(pw) != password {
					return
				}
				cmd, err := r.ReadByte()
				if err != nil || cmd != 0x01 {
					return
				}
				// 读目标地址。
				atyp, err := r.ReadByte()
				if err != nil {
					return
				}
				var host string
				switch atyp {
				case 0x01:
					b := make([]byte, 4)
					io.ReadFull(r, b)
					host = net.IP(b).String()
				case 0x03:
					n, _ := r.ReadByte()
					b := make([]byte, int(n))
					io.ReadFull(r, b)
					host = string(b)
				}
				var pb [2]byte
				io.ReadFull(r, pb[:])
				port := int(pb[0])<<8 | int(pb[1])
				r.ReadString('\n') // CRLF
				remote, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					return
				}
				defer remote.Close()
				// 把 reader 里已缓冲的数据转发出去，然后 relay。
				go io.Copy(remote, r)
				io.Copy(c, remote)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestTrojanOutboundEndToEnd(t *testing.T) {
	const password = "trojan-pwd"
	echo := startEcho(t)
	server := startTrojanServer(t, password)

	k := NewKernel()
	k.Proxies["TJ"] = NewTrojan("TJ", server, password, false, "", false)
	k.AddRules([]string{"MATCH,,TJ"})
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
	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))
	host, portStr, _ := net.SplitHostPort(echo)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	ip := net.ParseIP(host).To4()
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("connect reply = %v, %v", rep, err)
	}
	c.Write([]byte("trojan-ok"))
	buf := make([]byte, 9)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "trojan-ok" {
		t.Fatalf("echo = %q", buf)
	}
	_ = context.Background()
}
