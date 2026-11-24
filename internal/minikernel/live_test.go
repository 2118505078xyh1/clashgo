package minikernel

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"clashgo/internal/dnsproto"
	"clashgo/internal/http3proto"
	"clashgo/internal/quicproto"
)

// 本文件的测试默认跳过；设置对应环境变量后即可对真实服务端做端到端验证。
// 用法见仓库根目录 VERIFY.md。

func liveEnv(t *testing.T, key, hint string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("set %s to run the live test (%s)", key, hint)
	}
	return v
}

func liveInsecure() bool {
	v := strings.ToLower(os.Getenv("CLASHGO_LIVE_INSECURE"))
	return v == "1" || v == "true" || v == "yes"
}

func liveTarget() string {
	if v := os.Getenv("CLASHGO_LIVE_TARGET"); v != "" {
		return v
	}
	return "www.google.com:80"
}

func splitTarget(t *testing.T) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(liveTarget())
	if err != nil {
		t.Fatal(err)
	}
	var port uint64
	for _, c := range portStr {
		port = port*10 + uint64(c-'0')
	}
	return host, uint16(port)
}

// checkHTTP 在已建立的连接上发一个 HTTP GET，验证能收到 HTTP 响应。
func checkHTTP(t *testing.T, conn net.Conn, host string) {
	t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read HTTP status: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "HTTP/") {
		t.Fatalf("not an HTTP response: %q", line)
	}
	t.Logf("HTTP status: %s", strings.TrimSpace(line))
}

// TestLivePublicH3 用我们的 QUIC + HTTP/3 客户端访问真实公网 HTTP/3 服务端。
// 这是 QUIC/HTTP3 与第三方实现互通的直接证据（无需凭据）。
func TestLivePublicH3(t *testing.T) {
	addr := liveEnv(t, "CLASHGO_H3_SERVER", "e.g. cloudflare.com:443")
	serverName := os.Getenv("CLASHGO_H3_SNI")
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quicproto.Dial(ctx, addr, serverName, "h3", false)
	if err != nil {
		t.Fatalf("QUIC dial %s: %v", addr, err)
	}
	defer conn.Close()
	resp, err := http3proto.Do(ctx, h3ConnAdapter{conn}, http3proto.Request{
		Method: "GET", Scheme: "https", Authority: serverName, Path: "/",
	})
	if err != nil {
		t.Fatalf("HTTP/3 GET /: %v", err)
	}
	if resp.Status < 100 || resp.Status >= 600 {
		t.Fatalf("unexpected HTTP/3 status %d", resp.Status)
	}
	t.Logf("live HTTP/3 response from %s: status %d", addr, resp.Status)
}

// TestLiveDoQViaDNS 通过 dns.go 的 doq:// nameserver 集成路径查询公网 DoQ。
func TestLiveDoQViaDNS(t *testing.T) {
	addr := liveEnv(t, "CLASHGO_DOQ_SERVER", "e.g. dns.adguard-dns.com:853")
	serverName := os.Getenv("CLASHGO_DOQ_SNI")
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m := new(dnsproto.Msg)
	m.SetQuestion(dnsproto.Fqdn("example.com"), dnsproto.TypeA)
	resp, err := exchangeDoQ(ctx, addr, serverName, m)
	if err != nil {
		t.Fatalf("DoQ via dns.go: %v", err)
	}
	ips := resp.AnswerIPs()
	if len(ips) == 0 {
		t.Fatal("DoQ response had no A record")
	}
	t.Logf("live DoQ answer: %v", net.IP(ips[0]))
}

// TestLiveHysteria2 对真实 Hysteria2 服务端做认证 + TCP 数据面端到端验证。
func TestLiveHysteria2(t *testing.T) {
	addr := liveEnv(t, "CLASHGO_LIVE_HY2_ADDR", "e.g. example.com:443")
	password := liveEnv(t, "CLASHGO_LIVE_HY2_PASSWORD", "server auth password")
	sni := os.Getenv("CLASHGO_LIVE_HY2_SNI")
	host, _, _ := net.SplitHostPort(addr)
	if sni == "" {
		sni = host
	}
	host, port := splitTarget(t)
	p := newHysteria2Real("live-hy2", addr, sni, password, liveInsecure(), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := p.DialContext(ctx, &Metadata{Network: "tcp", Host: host, DstPort: port})
	if err != nil {
		t.Fatalf("Hysteria2 dial: %v", err)
	}
	checkHTTP(t, conn, host)
}

// TestLiveTUIC 对真实 TUIC v5 服务端做认证 + TCP 数据面端到端验证。
func TestLiveTUIC(t *testing.T) {
	addr := liveEnv(t, "CLASHGO_LIVE_TUIC_ADDR", "e.g. example.com:443")
	uuid := liveEnv(t, "CLASHGO_LIVE_TUIC_UUID", "client UUID")
	password := liveEnv(t, "CLASHGO_LIVE_TUIC_PASSWORD", "client password")
	sni := os.Getenv("CLASHGO_LIVE_TUIC_SNI")
	host, _, _ := net.SplitHostPort(addr)
	if sni == "" {
		sni = host
	}
	targetHost, targetPort := splitTarget(t)
	p := newTUICReal("live-tuic", addr, uuid, password, sni, liveInsecure())
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := p.DialContext(ctx, &Metadata{Network: "tcp", Host: targetHost, DstPort: targetPort})
	if err != nil {
		t.Fatalf("TUIC dial: %v", err)
	}
	checkHTTP(t, conn, targetHost)
}

// TestLiveUDP 对真实服务端做 UDP 数据面验证（向公网 DNS 发一条 A 查询）。
func TestLiveUDP(t *testing.T) {
	addr := liveEnv(t, "CLASHGO_LIVE_HY2_ADDR", "e.g. example.com:443")
	password := liveEnv(t, "CLASHGO_LIVE_HY2_PASSWORD", "server auth password")
	sni := os.Getenv("CLASHGO_LIVE_HY2_SNI")
	host, _, _ := net.SplitHostPort(addr)
	if sni == "" {
		sni = host
	}
	p := newHysteria2Real("live-hy2-udp", addr, sni, password, liveInsecure(), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	pc, err := p.ListenPacket(ctx, &Metadata{Network: "udp"})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	m := new(dnsproto.Msg)
	m.SetQuestion(dnsproto.Fqdn("example.com"), dnsproto.TypeA)
	wire, err := dnsproto.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo(wire, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 4096)
	if err := pc.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	resp, err := dnsproto.Unpack(buf[:n])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(resp.AnswerIPs()) == 0 {
		t.Fatal("UDP DNS response had no answer")
	}
	t.Logf("live UDP DNS answer: %v", net.IP(resp.AnswerIPs()[0]))
}
