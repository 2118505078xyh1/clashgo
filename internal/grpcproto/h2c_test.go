package grpcproto

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// HPACK
// ---------------------------------------------------------------------------

func TestHPACKIntegerEncoding(t *testing.T) {
	// RFC 7541 Appendix C.1 的整数向量（prefix = 5）。
	cases := []struct {
		n    uint32
		want []byte
	}{
		{10, []byte{0x0a}},
		{1337, []byte{0x1f, 0x9a, 0x0a}},
	}
	for _, tc := range cases {
		got := appendVarInt(nil, 5, 0, tc.n)
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("appendVarInt(%d) = % x, want % x", tc.n, got, tc.want)
		}
		decoded, used, err := readVarInt(got, 0, 5)
		if err != nil || decoded != tc.n || used != len(got) {
			t.Fatalf("readVarInt(% x) = %d, %d, %v", got, decoded, used, err)
		}
	}
}

func TestHPACKStaticTableRoundtrip(t *testing.T) {
	fields := []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/example.Greeter/Chat"},
		{Name: ":authority", Value: "example.com:8080"},
		{Name: "content-type", Value: ContentType},
		{Name: "te", Value: "trailers"},
		{Name: "grpc-status", Value: "0"},
		{Name: "grpc-message", Value: "hello world"},
	}
	block := EncodeHeaders(fields)
	got, err := DecodeHeaders(block)
	if err != nil {
		t.Fatalf("DecodeHeaders: %v", err)
	}
	want := headerFieldMap(fields)
	have := headerFieldMap(got)
	for k, v := range want {
		if have[k] != v {
			t.Errorf("field %q = %q, want %q", k, have[k], v)
		}
	}
	// 静态表精确匹配应产出索引表示（:method POST = 0x83, :scheme http = 0x86）。
	if block[0] != 0x83 || block[1] != 0x86 {
		t.Errorf("first bytes = % x, want 83 86", block[:2])
	}
	if want := string(EncodeHeaders([]HeaderField{{Name: "te", Value: "trailers"}})); !strings.Contains(string(block), want) {
		t.Errorf("encoded block % x missing te:trailers literal", block)
	}
}

// huffmanEncodeForTest 用内置表做 Huffman 编码，仅用于测试解码器。
func huffmanEncodeForTest(s string) []byte {
	var x uint64
	var n uint
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		n += uint(huffmanCodeLen[c])
		x <<= huffmanCodeLen[c]
		x |= uint64(huffmanCodes[c])
		for n >= 8 {
			n -= 8
			out = append(out, byte(x>>n))
		}
	}
	if n > 0 {
		out = append(out, byte(x<<(8-n))|byte((1<<(8-n))-1))
	}
	return out
}

func TestHPACKHuffmanAllSymbols(t *testing.T) {
	// 所有 256 个字节都应能 Huffman 编码往返。
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	decoded, err := huffmanDecode(huffmanEncodeForTest(string(all)))
	if err != nil {
		t.Fatalf("huffmanDecode: %v", err)
	}
	if decoded != string(all) {
		t.Fatalf("huffman roundtrip mismatch: got %d bytes, want 256", len(decoded))
	}

	// RFC 7541 Appendix C.4 的已知向量："www.example.com"
	known := []byte{0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff}
	got, err := huffmanDecode(known)
	if err != nil || got != "www.example.com" {
		t.Fatalf("known Huffman vector = %q, %v", got, err)
	}
}

func TestHPACKDecodeHuffmanAndDynamicTable(t *testing.T) {
	// 第一个 block：增量索引一个自定义头（会写入动态表 index 62）。
	first := append([]byte{0x40}, append(appendString(nil, "x-custom"), appendString(nil, "v1")...)...)
	// 第二个 block：索引动态表 62（0xbe = 0x80 | 62）。
	second := []byte{0xbe}

	dec := NewDecoder(hpackDefaultMaxTab)
	f1, err := dec.Decode(first)
	if err != nil || len(f1) != 1 || f1[0].Name != "x-custom" || f1[0].Value != "v1" {
		t.Fatalf("first decode = %v, %v", f1, err)
	}
	f2, err := dec.Decode(second)
	if err != nil || len(f2) != 1 || f2[0].Name != "x-custom" || f2[0].Value != "v1" {
		t.Fatalf("dynamic table decode = %v, %v", f2, err)
	}

	// Huffman 编码的 literal（content-type: application/grpc）。
	val := "application/grpc"
	hval := huffmanEncodeForTest(val)
	block := appendVarInt(nil, 4, 0x00, 31) // content-type 的名字索引
	block = appendVarInt(block, 7, 0x80, uint32(len(hval)))
	block = append(block, hval...)
	fields, err := DecodeHeaders(block)
	if err != nil || len(fields) != 1 || fields[0].Value != val {
		t.Fatalf("Huffman literal decode = %v, %v", fields, err)
	}
}

// ---------------------------------------------------------------------------
// HTTP/2 帧
// ---------------------------------------------------------------------------

func TestH2FrameCodec(t *testing.T) {
	settings := newSettingsFrame(false,
		Setting{ID: settingInitialWindowSize, Value: h2AdvertisedWindow},
		Setting{ID: settingMaxConcurrentStreams, Value: 100},
	)
	var buf bytes.Buffer
	if err := writeFrameBinary(&buf, settings); err != nil {
		t.Fatal(err)
	}
	got, err := readFrameBinary(bytes.NewReader(buf.Bytes()), maxH2FramePayload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != FrameSettings || len(got.Payload) != 12 {
		t.Fatalf("settings frame = %+v", got)
	}
	parsed, err := parseSettings(got.Payload)
	if err != nil || len(parsed) != 2 || parsed[0].Value != h2AdvertisedWindow {
		t.Fatalf("parseSettings = %v, %v", parsed, err)
	}

	// DATA 帧的 PADDED 处理。
	padded := Frame{Type: FrameData, StreamID: 1, Flags: FlagPadded,
		Payload: append([]byte{2}, append([]byte("abc"), 0, 0)...)}
	data, err := frameData(padded)
	if err != nil || string(data) != "abc" {
		t.Fatalf("frameData padded = %q, %v", data, err)
	}

	// WINDOW_UPDATE 解析。
	wu := newWindowUpdateFrame(0, 65535)
	inc, err := parseWindowUpdate(wu.Payload)
	if err != nil || inc != 65535 {
		t.Fatalf("parseWindowUpdate = %d, %v", inc, err)
	}
}

// ---------------------------------------------------------------------------
// 最小 h2c gRPC 服务端 + 端到端往返
// ---------------------------------------------------------------------------

type mockH2CServer struct {
	ln     net.Listener
	status string // trailers 里的 grpc-status
}

func startMockH2CServer(t *testing.T, status string) *mockH2CServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockH2CServer{ln: ln, status: status}
	go s.serve(t)
	return s
}

func (s *mockH2CServer) addr() string { return s.ln.Addr().String() }

func (s *mockH2CServer) close() { s.ln.Close() }

func (s *mockH2CServer) serve(t *testing.T) {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var preface [24]byte
	if _, err := io.ReadFull(conn, preface[:]); err != nil {
		t.Errorf("server: read preface: %v", err)
		return
	}
	if string(preface[:]) != clientPreface {
		t.Errorf("server: bad preface %q", preface)
		return
	}

	// 读客户端 SETTINGS，回服务端 SETTINGS + ACK。
	f, err := readFrameBinary(conn, maxH2FramePayload)
	if err != nil || f.Type != FrameSettings || f.Flags&FlagAck != 0 {
		t.Errorf("server: client settings = %+v, %v", f, err)
		return
	}
	if err := writeFrameBinary(conn, newSettingsFrame(false)); err != nil {
		t.Errorf("server: settings: %v", err)
		return
	}
	f, err = readFrameBinary(conn, maxH2FramePayload)
	if err != nil || f.Type != FrameSettings || f.Flags&FlagAck == 0 {
		t.Errorf("server: settings ack = %+v, %v", f, err)
		return
	}

	// 读请求 HEADERS 并校验关键字段。
	f, err = readFrameBinary(conn, maxH2FramePayload)
	if err != nil || f.Type != FrameHeaders {
		t.Errorf("server: request headers = %+v, %v", f, err)
		return
	}
	block, err := frameData(f)
	if err != nil {
		t.Errorf("server: header block: %v", err)
		return
	}
	fields, err := DecodeHeaders(block)
	if err != nil {
		t.Errorf("server: decode headers: %v", err)
		return
	}
	h := headerFieldMap(fields)
	if h[":method"] != "POST" || h[":scheme"] != "http" || h["content-type"] != ContentType || h["te"] != "trailers" {
		t.Errorf("server: bad request headers %v", h)
		return
	}

	// 收请求 DATA，累积成 gRPC 消息帧。
	var req bytes.Buffer
	var connCredit, streamCredit int
	flushCredit := func() {
		if connCredit >= 32768 {
			writeFrameBinary(conn, newWindowUpdateFrame(0, uint32(connCredit)))
			writeFrameBinary(conn, newWindowUpdateFrame(1, uint32(streamCredit)))
			connCredit, streamCredit = 0, 0
		}
	}
	for {
		f, err = readFrameBinary(conn, maxH2FramePayload)
		if err != nil {
			t.Errorf("server: read data: %v", err)
			return
		}
		if f.Type == FrameData {
			payload, err := frameData(f)
			if err != nil {
				t.Errorf("server: frameData: %v", err)
				return
			}
			req.Write(payload)
			connCredit += len(payload)
			streamCredit += len(payload)
			flushCredit()
			if f.Flags&FlagEndStream != 0 {
				break
			}
			// 收到 3 条固定消息后即可回包（测试已知消息数）。
			if req.Len() >= 5+5+5+len("one")+len("two")+len("three") {
				break
			}
		}
	}

	// 解出客户端发的 gRPC 消息并原样回写。
	var replies []byte
	for req.Len() > 0 {
		payload, _, err := readFrame(&req, DefaultMaxMessageSize)
		if err != nil {
			t.Errorf("server: read gRPC frame: %v", err)
			return
		}
		// 直接手工编码 gRPC 帧追加到 replies。
		var hdr [5]byte
		binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
		replies = append(replies, hdr[:]...)
		replies = append(replies, payload...)
	}

	// 响应 HEADERS + DATA + trailers(END_STREAM)。
	respBlock := EncodeHeaders([]HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: ContentType},
	})
	if err := writeFrameBinary(conn, newHeadersFrame(1, respBlock, false)); err != nil {
		t.Errorf("server: resp headers: %v", err)
		return
	}
	if err := writeFrameBinary(conn, newDataFrame(1, replies, false)); err != nil {
		t.Errorf("server: resp data: %v", err)
		return
	}
	trailers := EncodeHeaders([]HeaderField{
		{Name: "grpc-status", Value: s.status},
		{Name: "grpc-message", Value: "all done"},
	})
	if err := writeFrameBinary(conn, newHeadersFrame(1, trailers, true)); err != nil {
		t.Errorf("server: trailers: %v", err)
	}
}

func runH2CRoundtrip(t *testing.T, viaDial bool, status string) error {
	t.Helper()
	srv := startMockH2CServer(t, status)
	defer srv.close()

	cfg := Config{Path: "/example.Greeter/Chat", Host: "example.com", H2C: true}
	var conn net.Conn
	var err error
	if viaDial {
		conn, err = Dial(context.Background(), srv.addr(), cfg)
	} else {
		conn, err = DialH2C(context.Background(), srv.addr(), cfg)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	msgs := []string{"one", "two", "three"}
	for _, m := range msgs {
		if _, err := conn.Write([]byte(m)); err != nil {
			return err
		}
	}
	want := strings.Join(msgs, "")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != want {
		t.Fatalf("h2c roundtrip = %q, want %q", got, want)
	}
	// 数据读完后应看到 trailers 的终止状态。
	_, err = conn.Read(make([]byte, 1))
	return err
}

func TestH2CRoundtrip(t *testing.T) {
	if err := runH2CRoundtrip(t, false, "0"); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("DialH2C roundtrip: %v", err)
	}
}

func TestDialViaH2C(t *testing.T) {
	if err := runH2CRoundtrip(t, true, "0"); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Dial(H2C) roundtrip: %v", err)
	}
}

func TestH2CTrailersStatusError(t *testing.T) {
	err := runH2CRoundtrip(t, false, "13")
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v (%T), want *StatusError", err, err)
	}
	if se.Code != 13 || se.Message != "all done" {
		t.Fatalf("status error = %+v", se)
	}
}

// TestH2CLargeMessageFlowControl 验证发送超过初始窗口 65535 字节时，
// 服务端 WINDOW_UPDATE 能解锁后续 DATA 帧（不死锁）。
func TestH2CLargeMessageFlowControl(t *testing.T) {
	srv := startMockH2CServerLarge(t)
	defer srv.close()

	conn, err := DialH2C(context.Background(), srv.addr(), Config{Path: "/big/Stream"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("0123456789"), 20000) // 200 KB
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write large: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("Read large: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("large payload mismatch")
	}
}

func startMockH2CServerLarge(t *testing.T) *mockH2CServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockH2CServer{ln: ln, status: "0"}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		var preface [24]byte
		io.ReadFull(conn, preface[:])
		readFrameBinary(conn, maxH2FramePayload) // client SETTINGS
		writeFrameBinary(conn, newSettingsFrame(false))
		readFrameBinary(conn, maxH2FramePayload) // SETTINGS ACK
		readFrameBinary(conn, maxH2FramePayload) // request HEADERS

		reqLen := 5 + 200000
		// 把收到的 DATA 字节拼起来（一帧最多 16KB，循环直到够）。
		var buf bytes.Buffer
		var consumed int
		for buf.Len() < reqLen {
			f, err := readFrameBinary(conn, maxH2FramePayload)
			if err != nil {
				return
			}
			if f.Type != FrameData {
				continue
			}
			buf.Write(f.Payload)
			consumed += len(f.Payload)
			if consumed >= 32768 {
				writeFrameBinary(conn, newWindowUpdateFrame(0, uint32(consumed)))
				writeFrameBinary(conn, newWindowUpdateFrame(1, uint32(consumed)))
				consumed = 0
			}
		}
		// 回写同样的 gRPC 消息帧（原样回显请求字节）。
		writeFrameBinary(conn, newHeadersFrame(1, EncodeHeaders([]HeaderField{
			{Name: ":status", Value: "200"},
		}), false))
		writeFrameBinary(conn, newDataFrame(1, buf.Bytes(), false))
		writeFrameBinary(conn, newHeadersFrame(1, EncodeHeaders([]HeaderField{
			{Name: "grpc-status", Value: "0"},
		}), true))
	}()
	return s
}
