package grpcproto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 帧编解码
// ---------------------------------------------------------------------------

func TestFrameCodec(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		comp bool
	}{
		{"empty", nil, false},
		{"one byte", []byte{0x7f}, false},
		{"text", []byte("hello gRPC bidi stream"), false},
		{"compressed flag", []byte("already gzipped-ish"), true},
		{"binary", bytes.Repeat([]byte{0x00, 0xff, 0x42}, 300), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeFrame(&buf, tc.data, tc.comp); err != nil {
				t.Fatalf("writeFrame: %v", err)
			}
			if got, want := buf.Len(), frameHeaderSize+len(tc.data); got != want {
				t.Fatalf("encoded size = %d, want %d", got, want)
			}
			// 校验大端长度字段。
			if got := buf.Bytes()[0]; got != boolByte(tc.comp) {
				t.Fatalf("compressed flag = %d, want %d", got, boolByte(tc.comp))
			}

			got, comp, err := readFrame(bytes.NewReader(buf.Bytes()), DefaultMaxMessageSize)
			if err != nil {
				t.Fatalf("readFrame: %v", err)
			}
			if comp != tc.comp {
				t.Fatalf("compressed = %v, want %v", comp, tc.comp)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("payload = %q, want %q", got, tc.data)
			}
		})
	}
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func TestFrameErrors(t *testing.T) {
	// 非法的压缩标志。
	bad := []byte{2, 0, 0, 0, 1, 'x'}
	if _, _, err := readFrame(bytes.NewReader(bad), 0); !errors.Is(err, ErrBadFrame) {
		t.Fatalf("bad flag: got %v, want ErrBadFrame", err)
	}

	// 长度超过上限。
	var tooLarge [frameHeaderSize]byte
	tooLarge[4] = 100 // 长度 = 100，上限给 10。
	if _, _, err := readFrame(bytes.NewReader(tooLarge[:]), 10); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("too large: got %v, want ErrFrameTooLarge", err)
	}

	// 截断的帧头 / 载荷。
	if _, _, err := readFrame(bytes.NewReader([]byte{0, 0, 0}), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated header: got %v, want io.ErrUnexpectedEOF", err)
	}
	truncated := []byte{0, 0, 0, 0, 5, 'a', 'b'}
	if _, _, err := readFrame(bytes.NewReader(truncated), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated payload: got %v, want io.ErrUnexpectedEOF", err)
	}
}

// ---------------------------------------------------------------------------
// 双向往返
// ---------------------------------------------------------------------------

// echoHandler 是一个最小化的 gRPC 风格服务端处理函数：读取请求体中的
// gRPC 帧，原样回写为响应帧。它先写 200 响应头并 Flush，使客户端的 Do
// 立即返回，从而形成两个独立的流方向。
func echoHandler(t *testing.T, done chan<- struct{}) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != ContentType {
			t.Errorf("content-type = %q, want %q", ct, ContentType)
		}
		if te := r.Header.Get("Te"); te != "trailers" {
			t.Errorf("te = %q, want trailers", te)
		}

		// HTTP/1.1 下必须显式启用全双工，否则 net/http 会在发送响应头前
		// 尝试排空请求体，造成客户端等待响应头 / 服务端等待请求体的死锁。
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			t.Errorf("EnableFullDuplex: %v", err)
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("ResponseWriter does not implement Flusher")
			return
		}
		flusher.Flush()

		for {
			payload, _, err := readFrame(r.Body, DefaultMaxMessageSize)
			if err != nil {
				// 客户端关闭流时：HTTP/1.1 得到 io.EOF，HTTP/2 得到
				// stream CANCEL，二者都是正常的流结束。
				return
			}
			if err := writeFrame(w, payload, false); err != nil {
				t.Errorf("server writeFrame: %v", err)
				return
			}
			flusher.Flush()
		}
	}
}

func echoServer(t *testing.T, done chan<- struct{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(echoHandler(t, done))
}

func TestConnBidirectionalRoundtrip(t *testing.T) {
	done := make(chan struct{})
	srv := echoServer(t, done)
	defer srv.Close()

	cfg := Config{ServiceName: "example.Greeter", Path: "/example.Greeter/Chat"}
	conn, err := Dial(context.Background(), strings.TrimPrefix(srv.URL, "http://"), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msgs := []string{"hello", "world grpc", "third-message-longer-than-frame"}
	var want bytes.Buffer
	for _, m := range msgs {
		want.WriteString(m)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, m := range msgs {
			if _, err := conn.Write([]byte(m)); err != nil {
				t.Errorf("conn.Write: %v", err)
				return
			}
		}
	}()

	// 读取恰好期望的字节数（用 1 字节缓冲促使每次 Read 都跨帧/帧内切换），
	// 验证帧边界对 net.Conn 调用方透明。
	got := make([]byte, want.Len())
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("roundtrip = %q, want %q", got, want.Bytes())
	}

	// 让服务端看到客户端流结束（END_STREAM）。
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server handler did not finish after Close")
	}
}

// TestConnBidirectionalRoundtripHTTP2 验证 cfg.TLS=true 时走标准库内置 HTTP/2
// 的路径：请求确实是 HTTP/2，且双向帧往返与 HTTP/1.1 完全一致。
func TestConnBidirectionalRoundtripHTTP2(t *testing.T) {
	done := make(chan struct{})
	handler := echoHandler(t, done)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("request protocol = %s, want HTTP/2", r.Proto)
		}
		handler(w, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	// StartTLS 已为 srv.Client() 配好受信证书与 ForceAttemptHTTP2。
	conn, err := dialWithClient(context.Background(), srv.Listener.Addr().String(),
		Config{TLS: true, ServiceName: "pb.Greeter"}, srv.Client())
	if err != nil {
		t.Fatalf("Dial (h2): %v", err)
	}
	defer conn.Close()

	msgs := []string{"over", "http2", "full-duplex stream"}
	go func() {
		for _, m := range msgs {
			if _, err := conn.Write([]byte(m)); err != nil {
				t.Errorf("conn.Write: %v", err)
				return
			}
		}
	}()

	want := strings.Join(msgs, "")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	if string(got) != want {
		t.Fatalf("roundtrip = %q, want %q", got, want)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server handler did not finish after Close")
	}
}

func TestConnReadDeadline(t *testing.T) {
	done := make(chan struct{})
	srv := echoServer(t, done)
	defer srv.Close()

	conn, err := Dial(context.Background(), strings.TrimPrefix(srv.URL, "http://"), Config{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read succeeded despite expired read deadline")
	}
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("Read error = %v, want a timeout net.Error", err)
	}
}

func TestBuildURL(t *testing.T) {
	cases := []struct {
		addr string
		cfg  Config
		want string
	}{
		{"example.com:443", Config{TLS: true}, "https://example.com:443/grpc/Stream"},
		{"127.0.0.1:8080", Config{ServiceName: "pb.Svc"}, "http://127.0.0.1:8080/pb.Svc/Stream"},
		{"h:1", Config{Path: "/custom/Method"}, "http://h:1/custom/Method"},
	}
	for _, tc := range cases {
		u, err := buildURL(tc.addr, tc.cfg)
		if err != nil {
			t.Fatalf("buildURL: %v", err)
		}
		if got := u.String(); got != tc.want {
			t.Fatalf("buildURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
