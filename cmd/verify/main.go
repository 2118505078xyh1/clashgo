// Command verify 对自研内核做端到端验证。
//
// 用法（详见仓库根目录 VERIFY.md）：
//
//	go run ./cmd/verify quic [addr] [sni]                  # 公网 QUIC + HTTP/3（默认 cloudflare.com:443）
//	go run ./cmd/verify hy2  <addr> <password> [target]    # 真实 Hysteria2 服务端
//	go run ./cmd/verify tuic <addr> <uuid> <password>      # 真实 TUIC v5 服务端
//	go run ./cmd/verify tun                                # TUN 前置条件检查（管理员 + TAP）
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"clashgo/internal/http3proto"
	"clashgo/internal/minikernel"
	"clashgo/internal/quicproto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "quic":
		err = cmdQUIC(os.Args[2:])
	case "hy2":
		err = cmdProxy(os.Args[2:], "hy2")
	case "tuic":
		err = cmdProxy(os.Args[2:], "tuic")
	case "tun":
		err = cmdTUN()
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func usage() {
	fmt.Println(`verify — 自研内核端到端验证工具

  verify quic [addr] [sni]                 公网 QUIC + HTTP/3（默认 cloudflare.com:443）
  verify hy2  <addr> <password> [target]   真实 Hysteria2 认证 + TCP 数据面
  verify tuic <addr> <uuid> <password>     真实 TUIC v5 认证 + TCP 数据面
  verify tun                               TUN 前置条件检查（管理员 + TAP）

环境变量：
  CLASHGO_INSECURE=1   跳过证书校验（自签证书的服务端）
  CLASHGO_TARGET       TCP 测试目标，默认 www.google.com:80`)
}

// cmdQUIC 用我们的 QUIC + HTTP/3 客户端访问真实公网服务端。
func cmdQUIC(args []string) error {
	addr, sni := "cloudflare.com:443", "cloudflare.com"
	if len(args) >= 1 {
		addr = args[0]
		sni, _, _ = net.SplitHostPort(addr)
	}
	if len(args) >= 2 {
		sni = args[1]
	}
	fmt.Printf("[quic] dialing %s (SNI=%s, ALPN=h3) ...\n", addr, sni)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := quicproto.Dial(ctx, addr, sni, "h3", false)
	if err != nil {
		return fmt.Errorf("QUIC dial: %w", err)
	}
	defer conn.Close()
	fmt.Println("[quic] TLS 1.3 handshake + QUIC OK")

	resp, err := http3proto.Do(ctx, h3Adapter{conn}, http3proto.Request{
		Method: "GET", Scheme: "https", Authority: sni, Path: "/",
	})
	if err != nil {
		return fmt.Errorf("HTTP/3 GET /: %w", err)
	}
	fmt.Printf("[quic] HTTP/3 response status = %d\n", resp.Status)
	if resp.Status < 100 || resp.Status >= 600 {
		return fmt.Errorf("unexpected status %d", resp.Status)
	}
	return nil
}

// cmdProxy 对真实 Hysteria2/TUIC 服务端做认证 + TCP 数据面验证。
func cmdProxy(args []string, kind string) error {
	insecure := os.Getenv("CLASHGO_INSECURE") == "1"

	var adapter minikernel.ProxyAdapter
	var sni string
	var targetArg string
	switch kind {
	case "hy2":
		if len(args) < 2 {
			return fmt.Errorf("usage: verify hy2 <addr> <password> [target] [sni]")
		}
		addr, password := args[0], args[1]
		if len(args) >= 3 {
			targetArg = args[2]
		}
		if len(args) >= 4 {
			sni = args[3]
		} else {
			sni = hostOf(addr)
		}
		adapter = minikernel.NewHysteria2Verifier(addr, sni, password, insecure)
	case "tuic":
		if len(args) < 3 {
			return fmt.Errorf("usage: verify tuic <addr> <uuid> <password> [target] [sni]")
		}
		addr, uuid, password := args[0], args[1], args[2]
		if len(args) >= 4 {
			targetArg = args[3]
		}
		if len(args) >= 5 {
			sni = args[4]
		} else {
			sni = hostOf(addr)
		}
		adapter = minikernel.NewTUICVerifier(addr, uuid, password, sni, insecure)
	}

	target := targetArg
	if target == "" {
		target = os.Getenv("CLASHGO_TARGET")
	}
	if target == "" {
		target = "www.google.com:80"
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	var port uint64
	for _, c := range portStr {
		port = port*10 + uint64(c-'0')
	}

	fmt.Printf("[%s] dialing %s -> %s ...\n", kind, sni, net.JoinHostPort(host, portStr))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := adapter.DialContext(ctx, &minikernel.Metadata{
		Network: "tcp", Host: host, DstPort: uint16(port),
	})
	if err != nil {
		return fmt.Errorf("%s dial: %w", kind, err)
	}
	defer conn.Close()
	fmt.Printf("[%s] auth + data plane connected\n", kind)

	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read HTTP response: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "HTTP/") {
		return fmt.Errorf("not an HTTP response: %q", line)
	}
	fmt.Printf("[%s] proxied HTTP status: %s\n", kind, strings.TrimSpace(line))
	return nil
}

func cmdTUN() error {
	name, err := minikernel.ProbeTAP()
	if err != nil {
		return fmt.Errorf("TUN 前置条件不满足: %w", err)
	}
	fmt.Printf("[tun] TAP adapter OK: %s\n", name)
	fmt.Println("[tun] 适配器可打开。运行 CLASHGO_TUN_LIVE=1 go test ./internal/minikernel/ -run TestLiveTUN -v 做实机收发验证。")
	return nil
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// h3Adapter 把 quicproto.Connection 适配成 http3proto.Connection。
type h3Adapter struct{ c quicproto.Connection }

func (a h3Adapter) OpenStream() (http3proto.Stream, error) {
	s, err := a.c.OpenStream()
	if err != nil {
		return nil, err
	}
	return h3Stream{s}, nil
}
func (a h3Adapter) OpenUniStream() (http3proto.Stream, error) {
	s, err := a.c.OpenUniStream()
	if err != nil {
		return nil, err
	}
	return h3Stream{s}, nil
}

type h3Stream struct{ quicproto.Stream }
