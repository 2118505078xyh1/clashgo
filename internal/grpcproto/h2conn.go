package grpcproto

// 最小 h2c 客户端（HTTP/2 over TCP，prior knowledge，RFC 7540/7541）。
//
// 连接建立后只开一个流（stream 1），承载一条 gRPC 双向流：
//   - 对 Conn.Write 暴露为「写入一个 gRPC 消息帧」；底层把它拆成 HTTP/2 DATA 帧；
//   - 对 Conn.Read 暴露为「从响应 DATA 帧解出的字节流」；trailers 中的
//     grpc-status/grpc-message 在 DATA 读完后作为错误返回。
//
// 本文件不导入任何第三方包。

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// clientPreface 是 RFC 7540 Section 3.5 规定的客户端连接前言。
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	initialStreamWindow = 65535 // HTTP/2 默认连接/流初始窗口
	h2AdvertisedWindow  = 16 << 20
	h2HandshakeTimeout  = 10 * time.Second
	h2DataChunkSize     = 32 << 10
)

// StatusError 表示服务端在 trailers 里返回了非 0 的 grpc-status。
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("grpcproto: grpc-status %d", e.Code)
	}
	return fmt.Sprintf("grpcproto: grpc-status %d: %s", e.Code, e.Message)
}

// ---------------------------------------------------------------------------
// 响应字节流
// ---------------------------------------------------------------------------

// h2Response 把 HTTP/2 DATA 帧的载荷拼成连续的字节流，实现 io.ReadCloser。
// 它保证 DATA 先于 trailers 错误被读出。
type h2Response struct {
	mu    sync.Mutex
	cond  *sync.Cond
	buf   bytes.Buffer
	err   error
	done  bool
	owner *h2ClientConn
}

func newH2Response(owner *h2ClientConn) *h2Response {
	r := &h2Response{owner: owner}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *h2Response) push(p []byte) {
	if len(p) == 0 {
		return
	}
	r.mu.Lock()
	r.buf.Write(p)
	r.cond.Signal()
	r.mu.Unlock()
}

// finish 设置流的终止状态。多次调用只有第一次生效。
func (r *h2Response) finish(err error) {
	r.mu.Lock()
	if !r.done {
		r.done = true
		r.err = err
		r.cond.Broadcast()
	}
	r.mu.Unlock()
}

func (r *h2Response) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.buf.Len() == 0 && !r.done {
		r.cond.Wait()
	}
	if r.buf.Len() > 0 {
		return r.buf.Read(p)
	}
	if r.err != nil {
		return 0, r.err
	}
	return 0, io.EOF
}

func (r *h2Response) Close() error {
	r.owner.close()
	return nil
}

// ---------------------------------------------------------------------------
// h2c 客户端连接
// ---------------------------------------------------------------------------

type h2ClientConn struct {
	conn     net.Conn
	streamID uint32
	resp     *h2Response
	dec      *Decoder

	writeMu sync.Mutex // 串行化对 conn 的所有帧写入

	mu             sync.Mutex
	cond           *sync.Cond // 与 mu 关联，窗口更新 / 关闭时唤醒写方
	streamWindow   int64
	connWindow     int64
	peerInitialWin uint32 // 服务端广播的 INITIAL_WINDOW_SIZE
	maxFrameSize   int
	recvCredit     int // 自上次 WINDOW_UPDATE 起已从网络读取的字节数
	closed         bool
	endSent        bool
	closeOnce      sync.Once
}

func newH2ClientConn(ctx context.Context, addr string, cfg Config) (*h2ClientConn, error) {
	var d net.Dialer
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	u, err := buildURL(addr, cfg)
	if err != nil {
		tcp.Close()
		return nil, err
	}
	host := u.Host
	if cfg.Host != "" {
		host = cfg.Host
	}
	path := u.Path
	if path == "" {
		path = "/"
	}

	h := &h2ClientConn{
		conn:           tcp,
		streamID:       1,
		streamWindow:   initialStreamWindow,
		connWindow:     initialStreamWindow,
		peerInitialWin: initialStreamWindow,
		maxFrameSize:   16384,
	}
	h.cond = sync.NewCond(&h.mu)
	h.dec = NewDecoder(hpackDefaultMaxTab)
	h.resp = newH2Response(h)

	if err := h.handshake(ctx, host, path); err != nil {
		tcp.Close()
		return nil, err
	}
	go h.readLoop()
	return h, nil
}

// handshake 发送前言与初始 SETTINGS，等服务端 SETTINGS，然后打开 stream 1。
// 任何在这一步失败的情况都被视为「对端不是 h2c 服务端」。
func (h *h2ClientConn) handshake(ctx context.Context, host, path string) error {
	// 用 goroutine 把 ctx 取消映射到关闭底层连接，避免阻塞在读上。
	hctx, cancel := context.WithTimeout(ctx, h2HandshakeTimeout)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-hctx.Done():
			h.conn.Close()
		case <-done:
		}
	}()

	// 连接前言 + 客户端 SETTINGS（一次 Write 发出）。
	h.writeMu.Lock()
	var preface bytes.Buffer
	preface.WriteString(clientPreface)
	settingsFrame := newSettingsFrame(false, Setting{
		ID:    settingInitialWindowSize,
		Value: h2AdvertisedWindow,
	})
	if err := writeFrameBinary(&preface, settingsFrame); err != nil {
		h.writeMu.Unlock()
		return err
	}
	_, err := h.conn.Write(preface.Bytes())
	h.writeMu.Unlock()
	if err != nil {
		return err
	}

	// 等服务端 SETTINGS（非 ACK）。HTTP/1.1 服务端会回 "HTTP/1.1 400 ..."，
	// 其前 3 字节会被当作超大帧长度，从而快速失败并触发回退。
	for {
		f, err := readFrameBinary(h.conn, maxH2FramePayload)
		if err != nil {
			return fmt.Errorf("h2: waiting for SETTINGS: %w", err)
		}
		if f.Type == FrameSettings && f.Flags&FlagAck == 0 {
			settings, err := parseSettings(f.Payload)
			if err != nil {
				return err
			}
			if err := h.applySettings(settings); err != nil {
				return err
			}
			if err := h.writeFrame(newSettingsFrame(true)); err != nil {
				return err
			}
			break
		}
		// PING 要回应；其他帧在 SETTINGS 之前到达均视为非 h2c。
		if f.Type == FramePing && f.Flags&FlagAck == 0 {
			var data [8]byte
			copy(data[:], f.Payload)
			if err := h.writeFrame(newPingFrame(data, true)); err != nil {
				return err
			}
			continue
		}
		if f.Type == FrameSettings && f.Flags&FlagAck != 0 {
			continue // 对端误发的 ACK，忽略
		}
		return fmt.Errorf("h2: unexpected frame type %d before SETTINGS", f.Type)
	}

	// 打开 stream 1：POST 请求头，END_HEADERS，但不 END_STREAM。
	fields := []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: host},
		{Name: "content-type", Value: ContentType},
		{Name: "te", Value: "trailers"},
	}
	return h.writeFrame(newHeadersFrame(h.streamID, EncodeHeaders(fields), false))
}

// writeFrame 串行写出一帧。
func (h *h2ClientConn) writeFrame(f Frame) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return writeFrameBinary(h.conn, f)
}

func (h *h2ClientConn) applySettings(settings []Setting) error {
	for _, s := range settings {
		switch s.ID {
		case settingInitialWindowSize:
			if s.Value > 0x7fffffff {
				return errors.New("h2: invalid INITIAL_WINDOW_SIZE")
			}
			h.mu.Lock()
			delta := int64(s.Value) - int64(h.peerInitialWin)
			h.peerInitialWin = s.Value
			h.streamWindow += delta
			if h.streamWindow > 0x7fffffff {
				h.streamWindow = 0x7fffffff
			}
			h.mu.Unlock()
			h.cond.Broadcast()
		case settingMaxFrameSize:
			if s.Value < 16384 {
				s.Value = 16384
			}
			if s.Value > 0xffffff {
				s.Value = 0xffffff
			}
			h.mu.Lock()
			h.maxFrameSize = int(s.Value)
			h.mu.Unlock()
		}
	}
	return nil
}

// addSendWindow 处理 WINDOW_UPDATE。
func (h *h2ClientConn) addSendWindow(streamID uint32, inc uint32) {
	if inc == 0 {
		return
	}
	h.mu.Lock()
	switch streamID {
	case 0:
		h.connWindow += int64(inc)
	case h.streamID:
		h.streamWindow += int64(inc)
	default:
		h.mu.Unlock()
		return
	}
	if h.connWindow > 0x7fffffff {
		h.connWindow = 0x7fffffff
	}
	if h.streamWindow > 0x7fffffff {
		h.streamWindow = 0x7fffffff
	}
	h.mu.Unlock()
	h.cond.Broadcast()
}

// writeData 把 p 拆成不超过流控窗口 / MAX_FRAME_SIZE 的 DATA 帧写出。
func (h *h2ClientConn) writeData(p []byte) error {
	for len(p) > 0 {
		h.mu.Lock()
		for h.streamWindow <= 0 || h.connWindow <= 0 {
			if h.closed {
				h.mu.Unlock()
				return io.ErrClosedPipe
			}
			h.cond.Wait()
		}
		n := len(p)
		if int64(n) > h.streamWindow {
			n = int(h.streamWindow)
		}
		if int64(n) > h.connWindow {
			n = int(h.connWindow)
		}
		if n > h.maxFrameSize {
			n = h.maxFrameSize
		}
		if n <= 0 {
			h.mu.Unlock()
			continue
		}
		h.streamWindow -= int64(n)
		h.connWindow -= int64(n)
		h.mu.Unlock()

		if err := h.writeFrame(newDataFrame(h.streamID, p[:n], false)); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// endStream 发送一个空的 DATA + END_STREAM，表示客户端请求半关闭。
func (h *h2ClientConn) endStream() error {
	h.mu.Lock()
	if h.endSent || h.closed {
		h.mu.Unlock()
		return nil
	}
	h.endSent = true
	h.mu.Unlock()
	return h.writeFrame(newDataFrame(h.streamID, nil, true))
}

// onDataConsumed 为已读入用户空间的字节归还流控信用。
func (h *h2ClientConn) onDataConsumed(n int) {
	h.mu.Lock()
	h.recvCredit += n
	if h.recvCredit < 32768 {
		h.mu.Unlock()
		return
	}
	inc := uint32(h.recvCredit)
	h.recvCredit = 0
	h.mu.Unlock()
	// 流与连接级窗口都补充；连接窗口默认只有 65535，必须补。
	_ = h.writeFrame(newWindowUpdateFrame(h.streamID, inc))
	_ = h.writeFrame(newWindowUpdateFrame(0, inc))
}

// close 关闭底层连接并唤醒所有等待者。
func (h *h2ClientConn) close() {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
		h.cond.Broadcast()
		_ = h.conn.Close()
		h.resp.finish(io.EOF)
	})
}

// fail 把错误交给读方并关闭连接。
func (h *h2ClientConn) fail(err error) {
	h.resp.finish(err)
	h.close()
}

// readLoop 解复用服务端发来的帧。
func (h *h2ClientConn) readLoop() {
	for {
		f, err := readFrameBinary(h.conn, maxH2FramePayload)
		if err != nil {
			h.resp.finish(err)
			h.close()
			return
		}
		switch f.Type {
		case FrameData:
			if f.StreamID != h.streamID {
				continue
			}
			payload, err := frameData(f)
			if err != nil {
				h.fail(err)
				return
			}
			if len(payload) > 0 {
				h.resp.push(payload)
				h.onDataConsumed(len(payload))
			}
			if f.Flags&FlagEndStream != 0 {
				h.resp.finish(nil)
			}

		case FrameHeaders:
			if f.StreamID != h.streamID {
				continue
			}
			block, err := h.readHeaderBlock(f)
			if err != nil {
				h.fail(err)
				return
			}
			fields, err := h.dec.Decode(block)
			if err != nil {
				h.fail(err)
				return
			}
			if f.Flags&FlagEndStream != 0 {
				// trailers：先让已缓存的 DATA 被读完，再交出状态错误。
				h.resp.finish(grpcStatusError(fields))
				continue // 继续处理 PING / WINDOW_UPDATE
			}
			if st := fieldValue(fields, ":status"); st != "" && st != "200" {
				h.fail(fmt.Errorf("h2: unexpected :status %s", st))
				return
			}

		case FrameSettings:
			if f.Flags&FlagAck != 0 {
				continue
			}
			settings, err := parseSettings(f.Payload)
			if err != nil {
				h.fail(err)
				return
			}
			if err := h.applySettings(settings); err != nil {
				h.fail(err)
				return
			}
			if err := h.writeFrame(newSettingsFrame(true)); err != nil {
				h.fail(err)
				return
			}

		case FramePing:
			if f.Flags&FlagAck == 0 {
				var data [8]byte
				copy(data[:], f.Payload)
				if err := h.writeFrame(newPingFrame(data, true)); err != nil {
					h.fail(err)
					return
				}
			}

		case FrameWindowUpdate:
			inc, err := parseWindowUpdate(f.Payload)
			if err != nil {
				h.fail(err)
				return
			}
			h.addSendWindow(f.StreamID, inc)

		case FrameRSTStream:
			var code uint32
			if len(f.Payload) >= 4 {
				code = binary.BigEndian.Uint32(f.Payload)
			}
			h.fail(fmt.Errorf("h2: RST_STREAM code %d", code))
			return

		case FrameGoAway:
			h.fail(errors.New("h2: GOAWAY"))
			return
		}
	}
}

// readHeaderBlock 读取完整的 HPACK block：若 HEADERS 没有 END_HEADERS，
// 则后续必须紧跟同一流的 CONTINUATION 帧。
func (h *h2ClientConn) readHeaderBlock(first Frame) ([]byte, error) {
	part, err := frameData(first)
	if err != nil {
		return nil, err
	}
	block := append([]byte(nil), part...)
	if first.Flags&FlagEndHeaders != 0 {
		return block, nil
	}
	for {
		f, err := readFrameBinary(h.conn, maxH2FramePayload)
		if err != nil {
			return nil, err
		}
		if f.Type != FrameContinuation || f.StreamID != first.StreamID {
			return nil, errors.New("h2: expected CONTINUATION frame")
		}
		block = append(block, f.Payload...)
		if f.Flags&FlagEndHeaders != 0 {
			return block, nil
		}
	}
}

// fieldValue 返回指定名字的第一个字段值。
func fieldValue(fields []HeaderField, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// grpcStatusError 从 trailers 中提取 gRPC 状态。
func grpcStatusError(fields []HeaderField) error {
	raw := fieldValue(fields, "grpc-status")
	if raw == "" {
		return nil
	}
	code, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("h2: invalid grpc-status %q", raw)
	}
	if code == 0 {
		return nil
	}
	msg := fieldValue(fields, "grpc-message")
	if decoded, err := url.QueryUnescape(msg); err == nil {
		msg = decoded
	}
	return &StatusError{Code: code, Message: msg}
}

// ---------------------------------------------------------------------------
// 对外 API
// ---------------------------------------------------------------------------

// DialH2C 用明文 HTTP/2（h2c prior knowledge）建立到 addr 的 gRPC 双向流，
// 返回与 Dial 相同语义的 net.Conn。
//
// 它不依赖 net/http、TLS 或任何第三方包：自己完成 preface/SETTINGS 握手、
// HPACK 头编解码、DATA 帧收发、流控、PING/SETTINGS ACK 与 trailers 解析。
// 返回的 Conn 复用本包已有的 gRPC 消息帧编解码与截止时间逻辑。
func DialH2C(ctx context.Context, addr string, cfg Config) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(addr) == "" {
		return nil, errors.New("grpcproto: empty address")
	}

	h, err := newH2ClientConn(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}

	// 请求方向：io.Pipe → HTTP/2 DATA 帧。Conn.Write 每次产生一个 gRPC
	// 消息帧（5 字节头 + 载荷），pump goroutine 只把它当作字节流拆帧。
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, h2DataChunkSize)
		for {
			n, readErr := pr.Read(buf)
			if n > 0 {
				if werr := h.writeData(buf[:n]); werr != nil {
					_ = pr.CloseWithError(werr)
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					_ = h.endStream()
				} else {
					h.fail(readErr)
				}
				return
			}
		}
	}()

	c := newConn(pw, h.resp, addr)
	c.cancelOn(ctx.Done())
	return c, nil
}
