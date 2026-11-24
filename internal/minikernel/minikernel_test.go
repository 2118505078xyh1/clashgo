package minikernel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestParseRule(t *testing.T) {
	tests := []struct {
		line, typ, payload, adapter string
	}{
		{"DOMAIN,example.com,DIRECT", "DOMAIN", "example.com", "DIRECT"},
		{"DOMAIN-SUFFIX,google.com,REJECT", "DOMAIN-SUFFIX", "google.com", "REJECT"},
		{"DOMAIN-KEYWORD,ads,REJECT", "DOMAIN-KEYWORD", "ads", "REJECT"},
		{"IP-CIDR,192.168.0.0/16,DIRECT", "IP-CIDR", "192.168.0.0/16", "DIRECT"},
		{"MATCH,,DIRECT", "MATCH", "", "DIRECT"},
	}
	for _, tt := range tests {
		r, err := ParseRule(tt.line)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", tt.line, err)
		}
		if r.Type() != tt.typ || r.Payload() != tt.payload || r.Adapter() != tt.adapter {
			t.Errorf("ParseRule(%q) = %s,%s,%s", tt.line, r.Type(), r.Payload(), r.Adapter())
		}
	}
	if _, err := ParseRule("BOGUS,a,b"); err == nil {
		t.Error("expected error for unsupported rule type")
	}
}

func TestRuleMatch(t *testing.T) {
	mustRule := func(line string) Rule {
		r, err := ParseRule(line)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	domain := mustRule("DOMAIN,example.com,DIRECT")
	suffix := mustRule("DOMAIN-SUFFIX,google.com,REJECT")
	keyword := mustRule("DOMAIN-KEYWORD,ads,REJECT")
	cidr := mustRule("IP-CIDR,192.168.0.0/16,DIRECT")
	match := mustRule("MATCH,,DIRECT")

	cases := []struct {
		r    Rule
		m    *Metadata
		want bool
	}{
		{domain, &Metadata{Host: "example.com"}, true},
		{domain, &Metadata{Host: "wwwexample.com"}, false},
		{suffix, &Metadata{Host: "www.google.com"}, true},
		{suffix, &Metadata{Host: "google.com"}, true},
		{suffix, &Metadata{Host: "notgoogle.com"}, false}, // 前导点防误匹配
		{suffix, &Metadata{Host: "oo.com"}, false},
		{keyword, &Metadata{Host: "ads.example.com"}, true},
		{cidr, &Metadata{DstIP: netip.MustParseAddr("192.168.1.5")}, true},
		{cidr, &Metadata{DstIP: netip.MustParseAddr("10.0.0.1")}, false},
		{match, &Metadata{}, true},
	}
	for i, c := range cases {
		if got, _ := c.r.Match(c.m); got != c.want {
			t.Errorf("case %d: Match(%q) = %v, want %v", i, c.m.Host, got, c.want)
		}
	}
}

func TestRouteFirstMatchWins(t *testing.T) {
	k := NewKernel()
	k.AddRules([]string{
		"DOMAIN-SUFFIX,google.com,REJECT",
		"MATCH,,DIRECT",
	})
	m := &Metadata{Host: "www.google.com", Network: "tcp", DstPort: 443}
	remote, err := k.route(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	// REJECT 返回的连接读即 EOF。
	buf := make([]byte, 1)
	if n, err := remote.Read(buf); n != 0 || err != io.EOF {
		t.Errorf("REJECT conn read = %d,%v; want 0,EOF", n, err)
	}
}

// startEcho 启动一个回显 TCP 服务，返回地址。
func startEcho(t *testing.T) string {
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
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSOCKS5CONNECT(t *testing.T) {
	echo := startEcho(t)
	k := NewKernel() // 无规则 → DIRECT
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

	// SOCKS5 握手：方法协商。
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0x00 {
		t.Fatalf("method reply = %v, %v", reply, err)
	}
	// CONNECT 到 echo（IPv4）。
	host, portStr, _ := net.SplitHostPort(echo)
	port, _ := net.LookupPort("tcp", portStr)
	ip := net.ParseIP(host).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("connect reply = %v, %v", rep, err)
	}
	// 回显验证。
	msg := []byte("hello-minikernel")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Errorf("echo = %q, want %q", got, msg)
	}
	waitStats(t, k)
}

func TestHTTPCONNECT(t *testing.T) {
	echo := startEcho(t)
	k := NewKernel()
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

	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo, echo)
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil || !contains(line, "200") {
		t.Fatalf("connect response = %q, %v", line, err)
	}
	// 读完响应头。
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	msg := []byte("http-tunnel-ok")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

func waitStats(t *testing.T, k *Kernel) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if k.Stats().ActiveConns == 0 && k.Stats().UploadTotal > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("stats after test: %+v", k.Stats())
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
