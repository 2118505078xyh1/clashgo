package http3proto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Huffman（RFC 7541 Appendix B / RFC 9204 Section 4.1.2）
// ---------------------------------------------------------------------------

func TestHuffmanKnownVector(t *testing.T) {
	// RFC 7541 Appendix C.4.1 中 "www.example.com" 的 Huffman 编码。
	const want = "f1e3c2e5f23a6ba0ab90f4ff"
	got := hex.EncodeToString(HuffmanEncode([]byte("www.example.com")))
	if got != want {
		t.Fatalf("HuffmanEncode = %s, want %s", got, want)
	}
	decoded, err := HuffmanDecode(mustHex(t, want))
	if err != nil {
		t.Fatalf("HuffmanDecode: %v", err)
	}
	if string(decoded) != "www.example.com" {
		t.Fatalf("decoded = %q", decoded)
	}
}

func TestHuffmanRoundTrip(t *testing.T) {
	cases := []string{
		"", "a", "0", "/", "www.example.com", "no-cache", "gzip, deflate, br",
		"POST", "https", "hysteria", "Hysteria-Auth", "Hysteria-CC-RX",
		strings.Repeat("mixed 0123 /:?ABaz~", 7),
	}
	for _, s := range cases {
		encoded := HuffmanEncode([]byte(s))
		decoded, err := HuffmanDecode(encoded)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		if string(decoded) != s {
			t.Fatalf("roundtrip %q -> %q", s, decoded)
		}
	}

	// 全部 256 种字节值的往返。
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	decoded, err := HuffmanDecode(HuffmanEncode(all))
	if err != nil {
		t.Fatalf("decode all bytes: %v", err)
	}
	if !bytes.Equal(decoded, all) {
		t.Fatal("all-bytes roundtrip mismatch")
	}
}

func TestHuffmanDecodeErrors(t *testing.T) {
	// 0x18 = 'a'(00011) + 3 bit 填充 000，填充不是 EOS 高位（全 1）。
	if _, err := HuffmanDecode([]byte{0x18}); err == nil {
		t.Fatal("expected error for invalid padding")
	}
	// EOS 码（30 个 1）不能作为符号出现。
	if _, err := HuffmanDecode(mustHex(t, "3fffffff")); err == nil {
		t.Fatal("expected error for EOS symbol")
	}
	// 非法码字（全 0 的 30 bit 不是任何码字的前缀）。
	if _, err := HuffmanDecode(mustHex(t, "000000")); err == nil {
		t.Fatal("expected error for invalid code")
	}
}

// ---------------------------------------------------------------------------
// QUIC varint 与 HTTP/3 帧
// ---------------------------------------------------------------------------

func TestVarint(t *testing.T) {
	values := []uint64{0, 1, 62, 63, 64, 127, 128, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1}
	for _, v := range values {
		var buf bytes.Buffer
		buf.Write(appendVarint(nil, v))
		if buf.Len() != varintLen(v) {
			t.Fatalf("varintLen(%d) = %d, encoded %d", v, varintLen(v), buf.Len())
		}
		got, err := readVarint(&buf)
		if err != nil {
			t.Fatalf("readVarint(%d): %v", v, err)
		}
		if got != v || buf.Len() != 0 {
			t.Fatalf("varint roundtrip %d -> %d, leftover %d", v, got, buf.Len())
		}
	}
}

func TestVarintTruncated(t *testing.T) {
	// 2 字节 varint 只给了首字节。
	if _, err := readVarint(bytes.NewReader([]byte{0x40})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v", err)
	}
	if _, err := readVarint(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("got %v", err)
	}
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, FrameSettings, encodeSettings(map[uint64]uint64{
		SettingQpackMaxTableCapacity: 0,
		SettingEnableConnectProtocol: 1,
	})); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, FrameHeaders, []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, FrameData, nil); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, FrameGoAway, encodeGoAway(42)); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(buf.Bytes())
	f1, err := readFrame(r)
	if err != nil || f1.Type != FrameSettings {
		t.Fatalf("frame1 = %+v, %v", f1, err)
	}
	settings, err := decodeSettings(f1.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if settings[SettingQpackMaxTableCapacity] != 0 || settings[SettingEnableConnectProtocol] != 1 {
		t.Fatalf("settings = %v", settings)
	}

	f2, err := readFrame(r)
	if err != nil || f2.Type != FrameHeaders || !bytes.Equal(f2.Payload, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("frame2 = %+v, %v", f2, err)
	}
	f3, err := readFrame(r)
	if err != nil || f3.Type != FrameData || len(f3.Payload) != 0 {
		t.Fatalf("frame3 = %+v, %v", f3, err)
	}
	f4, err := readFrame(r)
	if err != nil || f4.Type != FrameGoAway {
		t.Fatalf("frame4 = %+v, %v", f4, err)
	}
	last, err := decodeGoAway(f4.Payload)
	if err != nil || last != 42 {
		t.Fatalf("goaway = %d, %v", last, err)
	}
	if _, err := readFrame(r); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// QPACK field section
// ---------------------------------------------------------------------------

func TestStaticTableIndices(t *testing.T) {
	// RFC 9204 Appendix A：POST=20, https=23, "/"=1, :authority=0, 200=25。
	cases := []struct {
		name, value string
		want        int
	}{
		{":method", "POST", 20},
		{":scheme", "https", 23},
		{":path", "/", 1},
		{":authority", "", 0},
		{":status", "200", 25},
	}
	for _, c := range cases {
		got, ok := staticFieldIndex(c.name, c.value)
		if !ok || got != c.want {
			t.Errorf("staticFieldIndex(%q,%q) = %d,%v; want %d", c.name, c.value, got, ok, c.want)
		}
	}
	if len(qpackStaticTable) != 99 {
		t.Fatalf("static table size = %d", len(qpackStaticTable))
	}
}

func TestEncodeFieldSectionRequestShape(t *testing.T) {
	block := EncodeFieldSection([]HeaderField{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", "hysteria"},
		{":path", "/auth"},
		{"Hysteria-Auth", "abc"},
	})
	// 00 00 = RequiredInsertCount=0, Base=0；D4/D7 = indexed POST/https；
	// 70 = literal name ref 到静态索引 0(:authority)（后面紧跟其 Huffman 值）。
	wantPrefix := []byte{0x00, 0x00, 0xd4, 0xd7, 0x70}
	if !bytes.HasPrefix(block, wantPrefix) {
		t.Fatalf("block prefix = %x, want %x", block[:minInt(len(block), 6)], wantPrefix)
	}
}

func TestFieldSectionRFC9204Vector(t *testing.T) {
	// RFC 9204 Appendix B.1: Literal Field Line with Name Reference。
	// N=0、无 Huffman，:path=/index.html → 00 00 51 0b "/index.html"。
	got := encodeFieldSection([]HeaderField{{":path", "/index.html"}}, false, false)
	want := mustHex(t, "0000510b2f696e6465782e68746d6c")
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded = %x, want %x", got, want)
	}
	fields, err := DecodeFieldSection(want)
	if err != nil {
		t.Fatal(err)
	}
	wantFields := []HeaderField{{":path", "/index.html"}}
	if !reflect.DeepEqual(fields, wantFields) {
		t.Fatalf("decoded = %+v, want %+v", fields, wantFields)
	}
}

func TestFieldSectionRoundTrip(t *testing.T) {
	fields := []HeaderField{
		{":method", "POST"},
		{":scheme", "https"},
		{":authority", "hysteria"},
		{":path", "/auth"},
		{"Hysteria-Auth", "dGVzdA=="},
		{"Hysteria-CC-RX", "10485760"},
		{"Hysteria-Padding", strings.Repeat("p", 64)},
		{"content-type", "application/json"}, // 静态表整项匹配
		{"x-custom-value", "a/b?c=d 0123"},   // literal name + Huffman
	}
	decoded, err := DecodeFieldSection(EncodeFieldSection(fields))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, fields) {
		t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", decoded, fields)
	}
}

func TestDecodeFieldSectionDynamicRefRejected(t *testing.T) {
	// Indexed Field Line，T=0（动态表）→ 必须报错。
	if _, err := DecodeFieldSection([]byte{0x00, 0x00, 0x80}); !errors.Is(err, ErrDynamicTableRef) {
		t.Fatalf("got %v", err)
	}
	// RequiredInsertCount != 0 → 必须报错。
	if _, err := DecodeFieldSection([]byte{0x01, 0x00}); !errors.Is(err, ErrDynamicTableRef) {
		t.Fatalf("got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Do：mock QUIC 流（net.Pipe，半关闭语义）
// ---------------------------------------------------------------------------

// mockAddr 实现 net.Addr。
type mockAddr string

func (a mockAddr) Network() string { return "mock-quic" }
func (a mockAddr) String() string  { return string(a) }

// half 是 QUIC 流的一个方向端点：r 读、w 写。Close 只关闭写方向（QUIC FIN）。
type half struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (h *half) Read(p []byte) (int, error)  { return h.r.Read(p) }
func (h *half) Write(p []byte) (int, error) { return h.w.Write(p) }
func (h *half) Close() error                { return h.w.Close() }
func (h *half) CloseWrite() error           { return h.w.Close() }
func (h *half) LocalAddr() net.Addr         { return mockAddr("local") }
func (h *half) RemoteAddr() net.Addr        { return mockAddr("remote") }

// io.Pipe 不支持 deadline；本 mock 的测试不用截止时间，故为空实现。
func (h *half) SetDeadline(t time.Time) error      { return nil }
func (h *half) SetReadDeadline(t time.Time) error  { return nil }
func (h *half) SetWriteDeadline(t time.Time) error { return nil }

type mockStream struct {
	id     uint64
	*half        // 客户端侧（Do 使用）
	server *half // 服务端侧（测试 handler 使用）
}

func newMockStream(id uint64) *mockStream {
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	return &mockStream{
		id:     id,
		half:   &half{r: s2cR, w: c2sW},
		server: &half{r: c2sR, w: s2cW},
	}
}

func (s *mockStream) StreamID() uint64 { return s.id }

type mockConn struct {
	mu       sync.Mutex
	nextID   uint64
	handlers []func(*mockStream)
	idx      int
}

func (c *mockConn) OpenUniStream() (Stream, error) { return c.open() }
func (c *mockConn) OpenStream() (Stream, error)    { return c.open() }

func (c *mockConn) open() (Stream, error) {
	c.mu.Lock()
	id := c.nextID
	c.nextID += 4
	var handler func(*mockStream)
	if c.idx < len(c.handlers) {
		handler = c.handlers[c.idx]
		c.idx++
	}
	c.mu.Unlock()

	s := newMockStream(id)
	if handler != nil {
		go handler(s)
	}
	return s, nil
}

func TestDoAuthRequest(t *testing.T) {
	var (
		mu             sync.Mutex
		controlChecked bool
		requestChecked bool
		wg             sync.WaitGroup
	)
	wg.Add(2)
	conn := &mockConn{handlers: []func(*mockStream){
		// 1) 控制流：类型 + SETTINGS。
		func(s *mockStream) {
			defer wg.Done()
			typ, err := readVarint(s.server)
			if err != nil {
				t.Errorf("control stream type: %v", err)
				return
			}
			if typ != StreamTypeControl {
				t.Errorf("control stream type = %d", typ)
			}
			f, err := readFrame(s.server)
			if err != nil {
				t.Errorf("control frame: %v", err)
				return
			}
			if f.Type != FrameSettings {
				t.Errorf("control frame type = %d", f.Type)
			}
			settings, err := decodeSettings(f.Payload)
			if err != nil {
				t.Errorf("settings: %v", err)
				return
			}
			if settings[SettingQpackMaxTableCapacity] != 0 || settings[SettingQpackBlockedStreams] != 0 {
				t.Errorf("settings = %v", settings)
			}
			mu.Lock()
			controlChecked = true
			mu.Unlock()
		},
		// 2) 请求流：HEADERS + FIN，回一个 :status 233。
		func(s *mockStream) {
			defer wg.Done()
			f, err := readFrame(s.server)
			if err != nil {
				t.Errorf("request frame: %v", err)
				return
			}
			if f.Type != FrameHeaders {
				t.Errorf("request frame type = %d", f.Type)
			}
			fields, err := DecodeFieldSection(f.Payload)
			if err != nil {
				t.Errorf("decode request headers: %v", err)
				return
			}
			got := make(map[string]string)
			for _, f := range fields {
				got[f.Name] = f.Value
			}
			want := map[string]string{
				":method": "POST", ":scheme": "https", ":authority": "hysteria",
				":path": "/auth", "hysteria-auth": "secret", "hysteria-cc-rx": "10485760",
				"hysteria-padding": "xxxx",
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("request headers = %v, want %v", got, want)
			}
			mu.Lock()
			requestChecked = true
			mu.Unlock()

			// 请求方关闭发送方向后，这里应读到 EOF。
			if _, err := readFrame(s.server); !errors.Is(err, io.EOF) {
				t.Errorf("expected FIN after request, got %v", err)
			}
			resp := EncodeFieldSection([]HeaderField{
				{":status", "233"},
				{"hysteria-version", "2"},
			})
			if err := writeFrame(s.server, FrameHeaders, resp); err != nil {
				t.Errorf("write response: %v", err)
			}
			_ = s.server.Close() // 服务端 FIN（Do 在读到最终 HEADERS 后即返回）
		},
	}}

	req := AuthRequest("secret", "10485760", "xxxx", "hysteria")
	resp, err := Do(context.Background(), conn, req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 233 {
		t.Fatalf("status = %d, want 233", resp.Status)
	}
	if resp.Headers["hysteria-version"] != "2" {
		t.Fatalf("response headers = %v", resp.Headers)
	}
	if _, ok := resp.Headers[":status"]; ok {
		t.Fatal(":status should not be in Headers")
	}
	// Do 在读到响应 HEADERS 后即返回，控制流 handler 可能尚未跑完；等两者结束。
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handlers did not finish in time")
	}
	mu.Lock()
	defer mu.Unlock()
	if !controlChecked || !requestChecked {
		t.Fatalf("handlers not done: control=%v request=%v", controlChecked, requestChecked)
	}
}

func TestDoSkipsInterimResponse(t *testing.T) {
	conn := &mockConn{handlers: []func(*mockStream){
		func(s *mockStream) {
			_, _ = readVarint(s.server)
			_, _ = readFrame(s.server) // SETTINGS
		},
		func(s *mockStream) {
			_, _ = readFrame(s.server) // request HEADERS
			_ = writeFrame(s.server, FrameHeaders,
				EncodeFieldSection([]HeaderField{{":status", "103"}}))
			_ = writeFrame(s.server, FrameHeaders,
				EncodeFieldSection([]HeaderField{{":status", "200"}, {"x-ok", "yes"}}))
			_ = s.server.Close()
		},
	}}
	resp, err := Do(context.Background(), conn, Request{
		Method: "POST", Scheme: "https", Authority: "hysteria", Path: "/auth",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || resp.Headers["x-ok"] != "yes" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestDoContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &mockConn{}
	if _, err := Do(ctx, conn, Request{Authority: "hysteria"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if conn.idx != 0 {
		t.Fatal("should not open streams for canceled context")
	}
}

func TestDoMissingAuthority(t *testing.T) {
	if _, err := Do(context.Background(), &mockConn{}, Request{}); err == nil {
		t.Fatal("expected error for missing authority")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
