package http3proto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

// 本包把 QUIC 层抽象为最小的流接口，因此不依赖 internal/quicproto 或任何
// 第三方 QUIC 实现。对接方只需让它的 QUIC stream 实现 net.Conn + StreamID，
// 让它的 QUIC connection 实现 OpenStream / OpenUniStream。
//
// 重要：Stream.Close()（或可选实现的 CloseWrite()）应当只关闭**发送方向**
// 并发出 QUIC FIN，而接收方向仍可继续读出响应。这正是 quic-go 的
// quic.Stream.Close() 语义。Do 在写完请求后立即关闭发送方向。
type Stream interface {
	net.Conn
	StreamID() uint64
}

// Connection 是能打开 QUIC 流的连接。
type Connection interface {
	OpenStream() (Stream, error)    // 客户端发起的双向流（请求流）
	OpenUniStream() (Stream, error) // 客户端发起的单向流（控制流）
}

// closeWriter 是 net.TCPConn 风格的「只关发送方向」接口。如果 QUIC stream
// 实现了它，Do 会优先使用它；否则退化为 Stream.Close()。
type closeWriter interface {
	CloseWrite() error
}

// Request 描述一次 HTTP/3 请求。Body 为空时只发一个带完整 field section 的
// HEADERS 帧；非空时额外发送 DATA 帧。
type Request struct {
	Method    string
	Scheme    string
	Authority string
	Path      string
	Headers   map[string]string
	Body      []byte // 可选请求体
}

// Response 是读到的最终响应（忽略 1xx 临时响应）。
type Response struct {
	Status  int
	Headers map[string]string
}

// AuthRequest 构造 Hysteria2 的认证请求：POST https://hysteria/auth。
// auth / ccRX / padding 分别是 Hysteria-Auth、Hysteria-CC-RX、Hysteria-Padding
// 头的值，由调用方按 Hysteria2 规则生成后原样传入。
func AuthRequest(auth, ccRX, padding, authority string) Request {
	if authority == "" {
		authority = "hysteria"
	}
	return Request{
		Method:    "POST",
		Scheme:    "https",
		Authority: authority,
		Path:      "/auth",
		Headers: map[string]string{
			"Hysteria-Auth":    auth,
			"Hysteria-CC-RX":   ccRX,
			"Hysteria-Padding": padding,
		},
	}
}

// Do 在 conn 上执行一次 HTTP/3 请求，返回最终响应的状态码和响应头。
//
// 流程（RFC 9114）：
//  1. 打开一条客户端单向流，首字节写流类型 0x00（control stream），随后写
//     SETTINGS 帧；该流保持打开，不发送 FIN。
//  2. 打开一条双向请求流，写 HEADERS 帧（QPACK encoded field section），
//     有 Body 时再写 DATA 帧；随后关闭发送方向（QUIC FIN）。
//  3. 从请求流读帧，QPACK 解码 HEADERS，取 :status，跳过 1xx 临时响应，
//     返回第一个最终响应（status >= 200）。
//
// 本包声明 SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 且不使用动态表，因此**不**
// 打开 QPACK encoder/decoder stream，也不发送任何 encoder stream 指令。
// 详见 doc.go 中的研究结论。
//
// 注意：每个 Connection 只应调用一次 Do。HTTP/3 规定每条连接只有一条控制流，
// 重复调用会打开第二条控制流，被服务端视为 H3_STREAM_CREATION_ERROR。
// Hysteria2 的认证场景本身就是「一条连接一次认证」，符合这一约束。
func Do(ctx context.Context, conn Connection, req Request) (*Response, error) {
	if conn == nil {
		return nil, errors.New("http3proto: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.Method == "" {
		req.Method = "POST"
	}
	if req.Scheme == "" {
		req.Scheme = "https"
	}
	if req.Path == "" {
		req.Path = "/"
	}
	if req.Authority == "" {
		return nil, errors.New("http3proto: empty :authority")
	}

	// 1) HTTP/3 control stream：类型 0x00 + SETTINGS，保持打开。
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		return nil, fmt.Errorf("http3proto: open control stream: %w", err)
	}
	if err := writeControlStream(ctrl); err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("http3proto: write control stream: %w", err)
	}
	// 成功时不关闭 ctrl：关闭关键流会被对端视为 H3_CLOSED_CRITICAL_STREAM。
	// 控制流的生命周期由 conn 的持有者管理。

	// 2) 请求流。
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("http3proto: open request stream: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(dl)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close() // 取消时唤醒阻塞的读/写
		case <-done:
		}
	}()

	if err := writeRequest(stream, req); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("http3proto: write request: %w", err)
	}
	// 关闭发送方向，相当于 HTTP/2 的 END_STREAM；HTTP/3 用 QUIC FIN 表达。
	if err := closeWrite(stream); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("http3proto: end request stream: %w", err)
	}

	// 3) 读响应。
	resp, err := readResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return resp, nil
}

func writeControlStream(s Stream) error {
	var head [8]byte
	b := appendVarint(head[:0], StreamTypeControl)
	if _, err := s.Write(b); err != nil {
		return err
	}
	// 声明不使用 QPACK 动态表，也不允许对端在动态表中阻塞我们的请求流。
	settings := map[uint64]uint64{
		SettingQpackMaxTableCapacity: 0,
		SettingQpackBlockedStreams:   0,
	}
	return writeFrame(s, FrameSettings, encodeSettings(settings))
}

func writeRequest(s Stream, req Request) error {
	fields := []HeaderField{
		{":method", req.Method},
		{":scheme", req.Scheme},
		{":authority", req.Authority},
		{":path", req.Path},
	}
	// HTTP/3 要求字段名小写；排序保证编码结果确定。
	// 注意：查值时必须用原始 key，不能用小写后的名字。
	type namedHeader struct{ original, lower string }
	names := make([]namedHeader, 0, len(req.Headers))
	for name := range req.Headers {
		lname := strings.ToLower(name)
		if strings.HasPrefix(lname, ":") {
			return fmt.Errorf("http3proto: pseudo-header in Headers: %q", name)
		}
		names = append(names, namedHeader{name, lname})
	}
	sort.Slice(names, func(i, j int) bool { return names[i].lower < names[j].lower })
	for _, h := range names {
		fields = append(fields, HeaderField{h.lower, req.Headers[h.original]})
	}

	if err := writeFrame(s, FrameHeaders, EncodeFieldSection(fields)); err != nil {
		return err
	}
	if len(req.Body) > 0 {
		return writeFrame(s, FrameData, req.Body)
	}
	return nil
}

func closeWrite(s Stream) error {
	if cw, ok := s.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return s.Close()
}

func readResponse(s Stream) (*Response, error) {
	for {
		frame, err := readFrame(s)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF // 流结束但没拿到最终响应
			}
			return nil, err
		}
		switch frame.Type {
		case FrameHeaders:
			fields, err := DecodeFieldSection(frame.Payload)
			if err != nil {
				return nil, fmt.Errorf("http3proto: decode response headers: %w", err)
			}
			status := 0
			headers := make(map[string]string, len(fields))
			for _, f := range fields {
				if f.Name == ":status" {
					if n, err := strconv.Atoi(f.Value); err == nil {
						status = n
					}
					continue
				}
				headers[f.Name] = f.Value
			}
			if status == 0 {
				return nil, errors.New("http3proto: response missing :status")
			}
			if status >= 100 && status < 200 {
				continue // 临时响应，继续读最终响应
			}
			return &Response{Status: status, Headers: headers}, nil
		case FrameData, FrameGoAway:
			// 认证响应没有有意义的 body；GOAWAY 也不会出现在请求流上。忽略。
			continue
		default:
			// RFC 9114 Section 9 允许忽略未知帧。
			continue
		}
	}
}
