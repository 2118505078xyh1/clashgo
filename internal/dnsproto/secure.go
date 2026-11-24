package dnsproto

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxDNSMessage 是 DNS 线格式报文的最大长度（TCP 长度前缀为 uint16）。
const maxDNSMessage = 0xFFFF

// ExchangeSecure 发起一次安全 DNS 查询，返回的语义与 ExchangeContext 相同。
// 它根据 server 的前缀自动选择传输方式：
//
//	"https://..." -> DoH（HTTP POST，application/dns-message）
//	"tls://..."   -> DoT（TLS over TCP，RFC 7858 的 2 字节长度前缀帧）
//	其它          -> 回退到原有的 UDP ExchangeContext
//
// c.Timeout 同时用于 DoH 的 HTTP 客户端超时与 DoT 的连接/读写超时；
// ctx 取消或超时会中断阻塞中的操作。DoT 省略端口时默认使用 853。
func (c *Client) ExchangeSecure(ctx context.Context, m *Msg, server string) (*Msg, time.Duration, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	switch {
	case strings.HasPrefix(server, "https://"):
		return c.exchangeDoH(ctx, m, server, start)
	case strings.HasPrefix(server, "tls://"):
		return c.exchangeDoT(ctx, m, server, start)
	default:
		return c.ExchangeContext(ctx, m, server)
	}
}

// exchangeDoH 实现 RFC 8484 的 wire-format POST 模式。
func (c *Client) exchangeDoH(ctx context.Context, m *Msg, rawURL string, start time.Time) (*Msg, time.Duration, error) {
	b, err := Pack(m)
	if err != nil {
		return nil, time.Since(start), err
	}
	if len(b) > maxDNSMessage {
		return nil, time.Since(start), ErrMessageTooBig
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		return nil, time.Since(start), err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	hc := &http.Client{Timeout: c.Timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, time.Since(start), fmt.Errorf("dnsproto: DoH server returned %s", resp.Status)
	}
	// 限制读取长度，避免恶意/异常服务端返回无限大的响应体。
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, time.Since(start), err
	}
	if len(body) > maxDNSMessage {
		return nil, time.Since(start), ErrMessageTooBig
	}

	answer, err := Unpack(body)
	if err != nil {
		return nil, time.Since(start), err
	}
	if answer.ID != m.ID {
		return nil, time.Since(start), fmt.Errorf("dnsproto: DoH response ID %d != query ID %d", answer.ID, m.ID)
	}
	return answer, time.Since(start), nil
}

// exchangeDoT 实现 RFC 7858：TCP 上的每条 DNS 报文前带 2 字节大端长度。
func (c *Client) exchangeDoT(ctx context.Context, m *Msg, server string, start time.Time) (*Msg, time.Duration, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, time.Since(start), err
	}
	host := u.Hostname()
	if host == "" {
		return nil, time.Since(start), fmt.Errorf("dnsproto: DoT server %q has no host", server)
	}
	port := u.Port()
	if port == "" {
		port = "853"
	}
	addr := net.JoinHostPort(host, port)

	b, err := Pack(m)
	if err != nil {
		return nil, time.Since(start), err
	}
	if len(b) > maxDNSMessage {
		return nil, time.Since(start), ErrMessageTooBig
	}

	d := net.Dialer{}
	if c.Timeout > 0 {
		d.Timeout = c.Timeout
	}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer raw.Close()
	// ctx 即使没有 deadline，取消时也要立刻打断阻塞的读写。
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	if deadline := secureDeadline(start, c.Timeout, ctx); !deadline.IsZero() {
		_ = raw.SetDeadline(deadline)
	}

	conn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, time.Since(start), err
	}

	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(b)))
	if err := writeAll(conn, head[:]); err != nil {
		return nil, time.Since(start), err
	}
	if err := writeAll(conn, b); err != nil {
		return nil, time.Since(start), err
	}

	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, time.Since(start), err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 || n > maxDNSMessage {
		return nil, time.Since(start), fmt.Errorf("dnsproto: DoT invalid message length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, time.Since(start), err
	}

	answer, err := Unpack(body)
	if err != nil {
		return nil, time.Since(start), err
	}
	if answer.ID != m.ID {
		return nil, time.Since(start), fmt.Errorf("dnsproto: DoT response ID %d != query ID %d", answer.ID, m.ID)
	}
	return answer, time.Since(start), nil
}

// secureDeadline 取 c.Timeout 与 ctx deadline 中较早的一个；都未设置时返回零值。
func secureDeadline(start time.Time, timeout time.Duration, ctx context.Context) time.Time {
	var deadline time.Time
	if timeout > 0 {
		deadline = start.Add(timeout)
	}
	if dl, ok := ctx.Deadline(); ok && (deadline.IsZero() || dl.Before(deadline)) {
		deadline = dl
	}
	return deadline
}
