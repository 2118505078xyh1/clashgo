package grpcproto

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ContentType 是 gRPC 请求/响应的内容类型。
const ContentType = "application/grpc"

// Config 描述 gRPC 双向流的建连参数。
//
//	ServiceName  gRPC 服务名，例如 "example.Greeter"（用于生成默认 Path）
//	Path         请求路径，例如 "/example.Greeter/Chat"；为空时自动生成
//	Host         HTTP :authority / Host 头；为空时使用 addr
//	TLS          true 表示使用 HTTPS（从而启用标准库 HTTP/2 + ALPN）
//	ServerName   TLS SNI 名称；为空时从 addr 推导
//	H2C          TLS=false 时是否使用明文 HTTP/2（h2c prior knowledge）。
//	             设为 true 可与真实 gRPC 服务端互通；默认 false 保持旧的
//	             HTTP/1.1 行为，以兼容既有自建服务端（新增字段，不影响旧代码）。
type Config struct {
	ServiceName string
	Path        string
	Host        string
	TLS         bool
	ServerName  string
	H2C         bool
}

// Dial 建立到 addr 的 gRPC 双向流，并以 net.Conn 形式返回。
//
// 它用 io.Pipe 作为长连接 POST 的请求体：调用方对 Conn.Write 的每次调用都会
// 产生一个 gRPC 消息帧，持续流入服务端（客户端流）；服务端返回的字节流被
// 解帧后由 Conn.Read 读取（服务端流）。两个方向互不阻塞。
//
// 当 cfg.TLS = true 时，Transport.ForceAttemptHTTP2 会让标准库在 ALPN 协商
// 成功后自动使用内置 HTTP/2。当 cfg.TLS = false 且 cfg.H2C = true 时，
// 走本包自带的 h2c prior-knowledge 客户端（DialH2C），可与真实 gRPC 服务端
// 互通；cfg.H2C 默认 false 以保持旧的 HTTP/1.1 行为（兼容既有自建服务端）。
func Dial(ctx context.Context, addr string, cfg Config) (net.Conn, error) {
	if !cfg.TLS && cfg.H2C {
		return DialH2C(ctx, addr, cfg)
	}
	serverName := cfg.ServerName
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(addr)
		if serverName == "" {
			serverName = addr
		}
	}

	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{ServerName: serverName},
	}
	client := &http.Client{Transport: tr}
	return dialWithClient(ctx, addr, cfg, client)
}

// dialWithClient 是 Dial 的内部版本，允许注入自定义 http.Client（测试用）。
func dialWithClient(ctx context.Context, addr string, cfg Config, client *http.Client) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("grpcproto: empty address")
	}

	u, err := buildURL(addr, cfg)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), pr)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, err
	}
	req.Header.Set("Content-Type", ContentType)
	// gRPC 要求 HTTP/2 的 TE: trailers；标准库 HTTP/2 会原样写出该头。
	req.Header.Set("Te", "trailers")
	if cfg.Host != "" {
		req.Host = cfg.Host
	}

	resp, err := client.Do(req)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("grpcproto: unexpected status %s", resp.Status)
	}

	c := newConn(pw, resp.Body, addr)
	c.cancelOn(ctx.Done())
	return c, nil
}

// buildURL 根据 addr 与 cfg 构造请求 URL。
func buildURL(addr string, cfg Config) (*url.URL, error) {
	// 允许调用方在 addr 里带上 scheme，统一去掉后由 cfg.TLS 决定。
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimSuffix(addr, "/")
	if addr == "" {
		return nil, errors.New("grpcproto: empty address")
	}

	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}

	path := cfg.Path
	if path == "" {
		name := strings.Trim(cfg.ServiceName, "/")
		if name == "" {
			name = "grpc"
		}
		path = "/" + name + "/Stream"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return &url.URL{Scheme: scheme, Host: addr, Path: path}, nil
}
