package minikernel

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"clashgo/internal/grpcproto"
	"clashgo/internal/reality"
	"clashgo/internal/ws"
)

// transportSpec 描述出站底层传输（TCP / TLS / WS / WSS）。
type transportSpec struct {
	Server     string
	Network    string
	TLS        bool
	ServerName string
	Path       string
	Host       string
	SkipVerify bool
	Reality    *reality.Config
}

// dialTransport 按配置建立底层连接（TCP / WebSocket / gRPC，可选 TLS）。
func dialTransport(ctx context.Context, spec transportSpec) (net.Conn, error) {
	// gRPC 传输：标准库 HTTP/2 双向流（ForceAttemptHTTP2）。
	if strings.EqualFold(spec.Network, "grpc") {
		grpcCfg := grpcproto.Config{
			ServiceName: spec.Path, Path: spec.Path, Host: spec.Host,
			TLS:        spec.TLS,
			ServerName: spec.ServerName,
		}
		return grpcproto.Dial(ctx, spec.Server, grpcCfg)
	}
	isWS := spec.Network == "ws" || spec.Network == "http" || spec.Network == "h2"
	useTLS := spec.TLS || spec.Network == "wss"

	if isWS {
		scheme := "ws"
		if useTLS {
			scheme = "wss"
		}
		path := spec.Path
		if path == "" {
			path = "/"
		} else if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u := url.URL{Scheme: scheme, Host: spec.Server, Path: path}
		opts := &ws.DialOptions{HTTPHeader: http.Header{}}
		if spec.Host != "" {
			opts.Host = spec.Host
		}
		if useTLS {
			tlsCfg := &tls.Config{
				ServerName:         spec.ServerName,
				InsecureSkipVerify: spec.SkipVerify,
			}
			if tlsCfg.ServerName == "" {
				tlsCfg.ServerName, _, _ = net.SplitHostPort(spec.Server)
			}
			opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		}
		c, _, err := ws.Dial(ctx, u.String(), opts)
		if err != nil {
			return nil, err
		}
		return ws.NetConn(ctx, c, ws.MessageBinary), nil
	}

	netd := net.Dialer{Timeout: 10 * time.Second}
	raw, err := netd.DialContext(ctx, "tcp", spec.Server)
	if err != nil {
		return nil, err
	}
	if spec.Reality != nil {
		return reality.Dial(ctx, raw, *spec.Reality)
	}
	if !useTLS {
		return raw, nil
	}
	sni := spec.ServerName
	if sni == "" {
		sni, _, _ = net.SplitHostPort(spec.Server)
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: spec.SkipVerify})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tlsConn, nil
}
