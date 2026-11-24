package quicproto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 协议头编解码
// ---------------------------------------------------------------------------

func TestHeaderRoundTrip(t *testing.T) {
	cfg := Config{
		Password:  "h2-password",
		UUID:      "123e4567-e89b-12d3-a456-426614174000",
		Token:     "tuic-token",
		Bandwidth: 100,
	}

	h2Bytes, h2Salt, err := buildHysteria2Header(cfg, "example.com", 443)
	if err != nil {
		t.Fatalf("buildHysteria2Header: %v", err)
	}
	h2, err := parseHysteria2Header(h2Bytes)
	if err != nil {
		t.Fatalf("parseHysteria2Header: %v", err)
	}
	if h2.version != h2Version || h2.command != h2CmdConnect {
		t.Fatalf("bad h2 metadata: %+v", h2)
	}
	if h2.auth != authHash(cfg.Password) {
		t.Fatal("h2 auth hash mismatch")
	}
	if !bytes.Equal(h2.salt, h2Salt) {
		t.Fatal("h2 salt mismatch")
	}
	if h2.bandwidth != 100 || h2.target.host != "example.com" || h2.target.port != 443 {
		t.Fatalf("bad h2 target/bandwidth: %+v", h2)
	}

	tuBytes, tuSalt, err := buildTUICHeader(cfg, "1.2.3.4", 80)
	if err != nil {
		t.Fatalf("buildTUICHeader: %v", err)
	}
	tu, err := parseTUICHeader(tuBytes)
	if err != nil {
		t.Fatalf("parseTUICHeader: %v", err)
	}
	if tu.version != tuicVersion || tu.tokenHash != authHash(cfg.Token) {
		t.Fatalf("bad tuic metadata: %+v", tu)
	}
	if !bytes.Equal(tu.salt, tuSalt) || tu.target.host != "1.2.3.4" || tu.target.port != 80 {
		t.Fatalf("bad tuic salt/target: %+v", tu)
	}
	if u, _ := parseUUID(cfg.UUID); tu.uuid != u {
		t.Fatal("tuic uuid mismatch")
	}
}

func TestHeaderRejectsBadMagic(t *testing.T) {
	if _, err := parseHysteria2Header([]byte("XX")); err == nil {
		t.Fatal("expected h2 magic error")
	}
	if _, err := parseTUICHeader([]byte("XX")); err == nil {
		t.Fatal("expected tuic magic error")
	}
}

// ---------------------------------------------------------------------------
// 可靠 UDP 层
// ---------------------------------------------------------------------------

func TestReliableLoopback(t *testing.T) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	serverDone := make(chan error, 1)
	go func() {
		server, err := acceptReliable(l)
		if err != nil {
			serverDone <- err
			return
		}
		defer server.Close()
		buf := make([]byte, 4096)
		var total int
		for total < 110000 {
			n, err := server.Read(buf)
			total += n
			if err != nil {
				serverDone <- err
				return
			}
			if _, err := writeFull(server, buf[:n]); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := dialReliable(ctx, l.LocalAddr().String())
	if err != nil {
		t.Fatalf("dialReliable: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(8 * time.Second))

	payload := bytes.Repeat([]byte("quicproto-reliable-udp"), 5000) // ~110 KB，跨多个窗口
	if _, err := writeFull(client, payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 完整出站拨号（客户端 + 简化版服务端回环）
// ---------------------------------------------------------------------------

func readAuthHeader(rc net.Conn, parse func([]byte) error) ([]byte, error) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for len(buf) < 1024 {
		n, err := rc.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return nil, err
		}
		if parse(buf) == nil {
			return buf, nil
		}
	}
	return nil, errors.New("auth header too large")
}

func TestDialWithSimplifiedServer(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		dial   func(context.Context, Config, string, uint16) (net.Conn, error)
		status byte
	}{
		{
			name:   "hysteria2",
			cfg:    Config{Server: "", Password: "h2-password", Bandwidth: 200},
			dial:   DialHysteria2,
			status: h2OK,
		},
		{
			name:   "tuic",
			cfg:    Config{Server: "", UUID: "123e4567-e89b-12d3-a456-426614174000", Token: "tuic-token"},
			dial:   DialTUIC,
			status: tuicOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()

			errCh := make(chan error, 1)
			go func() {
				rc, err := acceptReliable(l)
				if err != nil {
					errCh <- err
					return
				}
				defer rc.Close()

				if tt.name == "hysteria2" {
					b, err := readAuthHeader(rc, func(b []byte) error { _, e := parseHysteria2Header(b); return e })
					if err != nil {
						errCh <- err
						return
					}
					h, _ := parseHysteria2Header(b)
					if h.target.host != "example.org" || h.target.port != 8443 {
						errCh <- errors.New("bad target in h2 header")
						return
					}
					c2s, s2c, err := h2SessionAEAD(authHash(tt.cfg.Password), h.salt)
					if err != nil {
						errCh <- err
						return
					}
					rc.Write([]byte{h2OK})
					stream := newAEADStream(rc, c2s, s2c)
					buf := make([]byte, 4096)
					n, err := stream.Read(buf)
					if err != nil {
						errCh <- err
						return
					}
					if string(buf[:n]) != "hello-proxy" {
						errCh <- errors.New("bad plaintext from client")
						return
					}
					_, err = stream.Write([]byte("hello-client"))
					errCh <- err
				} else {
					b, err := readAuthHeader(rc, func(b []byte) error { _, e := parseTUICHeader(b); return e })
					if err != nil {
						errCh <- err
						return
					}
					h, _ := parseTUICHeader(b)
					if h.target.host != "example.org" || h.target.port != 8443 {
						errCh <- errors.New("bad target in tuic header")
						return
					}
					c2s, s2c, err := tuicSessionAEAD(authHash(tt.cfg.Token), h.salt)
					if err != nil {
						errCh <- err
						return
					}
					rc.Write([]byte{tuicOK})
					stream := newAEADStream(rc, c2s, s2c)
					buf := make([]byte, 4096)
					n, err := stream.Read(buf)
					if err != nil {
						errCh <- err
						return
					}
					if string(buf[:n]) != "hello-proxy" {
						errCh <- errors.New("bad plaintext from client")
						return
					}
					_, err = stream.Write([]byte("hello-client"))
					errCh <- err
				}
			}()

			cfg := tt.cfg
			cfg.Server = l.LocalAddr().String()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := tt.dial(ctx, cfg, "example.org", 8443)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

			if _, err := conn.Write([]byte("hello-proxy")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(buf[:n]) != "hello-client" {
				t.Fatalf("unexpected reply %q", buf[:n])
			}
			if err := <-errCh; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestDialAuthFailure(t *testing.T) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		rc, err := acceptReliable(l)
		if err != nil {
			return
		}
		defer rc.Close()
		readAuthHeader(rc, func(b []byte) error { _, e := parseHysteria2Header(b); return e })
		rc.Write([]byte{h2AuthFail})
	}()

	cfg := Config{Server: l.LocalAddr().String(), Password: "wrong"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = DialHysteria2(ctx, cfg, "example.org", 443)
	if err == nil || err.Error() != "quicproto: authentication failed" {
		t.Fatalf("expected auth failure, got %v", err)
	}
}
