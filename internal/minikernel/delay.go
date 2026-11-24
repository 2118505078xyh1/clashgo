package minikernel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DelayResult 是一次延迟测试的结果。
type DelayResult struct {
	Proxy string `json:"proxy"`
	Delay uint16 `json:"delay"` // 毫秒；0 表示失败
	Error string `json:"error,omitempty"`
}

// TestDelay 通过一个出站代理向 testURL 发 HEAD 请求，测量往返延迟（毫秒）。
func TestDelay(ctx context.Context, p ProxyAdapter, testURL string) DelayResult {
	result := DelayResult{Proxy: p.Name()}
	u, err := url.Parse(testURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	host := u.Hostname()
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if pStr := u.Port(); pStr != "" {
		if n, e := strconv.Atoi(pStr); e == nil {
			port = n
		}
	}
	metadata := &Metadata{Host: host, DstPort: uint16(port), Network: "tcp"}

	start := time.Now()
	conn, err := p.DialContext(ctx, metadata)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	// HTTPS 目标：连接建立后还需在连接上做内层 TLS 握手，
	// 再发 HTTP 请求（代理只转发字节，TLS 是客户端与目标之间的）。
	var rw io.ReadWriter = conn
	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: host})
		if err := tc.HandshakeContext(ctx); err != nil {
			result.Error = "tls handshake: " + err.Error()
			return result
		}
		rw = tc
	}
	fmt.Fprintf(rw, "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	line, err := bufio.NewReader(rw).ReadString('\n')
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if !strings.Contains(line, " 20") { // 2xx
		result.Error = "unexpected status: " + strings.TrimSpace(line)
		return result
	}
	result.Delay = uint16(time.Since(start) / time.Millisecond)
	return result
}

// TestGroupDelay 并发测试一个代理组所有成员的延迟，并回写 URLTest 的结果。
func TestGroupDelay(ctx context.Context, k *Kernel, group ProxyGroup, testURL string) []DelayResult {
	members := group.Members()
	results := make([]DelayResult, len(members))
	var wg sync.WaitGroup
	for i, name := range members {
		p, ok := k.Proxies[name]
		if !ok {
			results[i] = DelayResult{Proxy: name, Error: "proxy not found"}
			continue
		}
		wg.Add(1)
		go func(i int, name string, p ProxyAdapter) {
			defer wg.Done()
			r := TestDelay(ctx, p, testURL)
			r.Proxy = name
			results[i] = r
			switch g := group.(type) {
			case *URLTest:
				g.SetDelay(name, r.Delay)
			case *Fallback:
				g.SetDelay(name, r.Delay)
			}
		}(i, name, p)
	}
	wg.Wait()
	return results
}
