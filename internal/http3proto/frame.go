package http3proto

import (
	"errors"
	"fmt"
	"io"
)

// QUIC 可变长整数（RFC 9000 Section 16）与 HTTP/3 帧（RFC 9114 Section 7）。
//
// 注意：RFC 9114 最终版的帧格式是「Type(varint) + Length(varint) + Payload」，
// **没有** HTTP/2 那样的 Flags 字节，也没有 END_HEADERS / END_STREAM 标志位。
// HEADERS 帧的载荷就是一个完整的 QPACK encoded field section；流的结束由 QUIC
// 的 FIN（本包中即 Stream.Close()）表达。
//
// 这些函数只使用标准库，不依赖任何具体的 QUIC 实现。

// MaxFramePayload 是本包读帧时允许的单帧载荷上限（1 MiB），防止恶意长度导致
// 超大分配。Hysteria2 认证头远小于此值。
const MaxFramePayload uint64 = 1 << 20

var (
	// ErrVarintTooLarge 表示 QUIC varint 超过 62 bit 可表示范围。
	ErrVarintTooLarge = errors.New("http3proto: QUIC varint exceeds 62 bits")
	// ErrFrameTooLarge 表示帧载荷超过 MaxFramePayload。
	ErrFrameTooLarge = errors.New("http3proto: frame payload too large")
	// ErrBadFrame 表示帧载荷格式非法。
	ErrBadFrame = errors.New("http3proto: bad frame payload")
)

// ---------------------------------------------------------------------------
// QUIC varint
// ---------------------------------------------------------------------------

// appendVarint 按 RFC 9000 Section 16 追加一个 QUIC 可变长整数。
// 前缀 2 bit 表示长度：00=1B(6bit)、01=2B(14bit)、10=4B(30bit)、11=8B(62bit)。
func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default: // v < 1<<62（调用方负责不传入更大的值）
		return append(dst,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// varintLen 返回 appendVarint 编码 v 所需的字节数。
func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	default:
		return 8
	}
}

// readVarint 从 r 读取一个 QUIC 可变长整数。
// 干净流结束时返回 io.EOF；整数被截断时返回 io.ErrUnexpectedEOF。
func readVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	n := 1 << (first[0] >> 6)
	v := uint64(first[0] & 0x3f)
	if n > 1 {
		var rest [7]byte
		if _, err := io.ReadFull(r, rest[:n-1]); err != nil {
			if errors.Is(err, io.EOF) {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		for _, b := range rest[:n-1] {
			v = v<<8 | uint64(b)
		}
	}
	if n == 8 && v > 1<<62-1 {
		return 0, ErrVarintTooLarge
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// HTTP/3 帧
// ---------------------------------------------------------------------------

// RFC 9114 Section 11.2.1 定义的帧类型（本包实现其中四种）。
const (
	FrameData     uint64 = 0x0
	FrameHeaders  uint64 = 0x1
	FrameSettings uint64 = 0x4
	FrameGoAway   uint64 = 0x7
)

// HTTP/3 SETTINGS 参数 ID（RFC 9114 Section 11.2.2 / RFC 9204 Section 5）。
const (
	SettingQpackMaxTableCapacity uint64 = 0x01
	SettingMaxHeaderListSize     uint64 = 0x06
	SettingQpackBlockedStreams   uint64 = 0x07
	SettingEnableConnectProtocol uint64 = 0x08
)

// 客户端单向流的流类型（RFC 9114 Section 6.2 / RFC 9204 Section 4.2）。
const (
	StreamTypeControl      uint64 = 0x00 // HTTP/3 control stream
	StreamTypeQPACKEncoder uint64 = 0x02 // QPACK encoder stream
	StreamTypeQPACKDecoder uint64 = 0x03 // QPACK decoder stream
)

// Frame 是一条解出的 HTTP/3 帧。
type Frame struct {
	Type    uint64
	Payload []byte
}

// writeFrame 把一条帧写入 w：Type(varint) + Length(varint) + Payload。
func writeFrame(w io.Writer, typ uint64, payload []byte) error {
	if uint64(len(payload)) > MaxFramePayload {
		return fmt.Errorf("%w: %d", ErrFrameTooLarge, len(payload))
	}
	var hdr [16]byte
	b := appendVarint(hdr[:0], typ)
	b = appendVarint(b, uint64(len(payload)))
	if _, err := w.Write(b); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrame 从 r 读取一条帧。流干净结束时返回 io.EOF。
func readFrame(r io.Reader) (*Frame, error) {
	typ, err := readVarint(r)
	if err != nil {
		return nil, err
	}
	length, err := readVarint(r)
	if err != nil {
		return nil, err
	}
	if length > MaxFramePayload {
		return nil, fmt.Errorf("%w: %d", ErrFrameTooLarge, length)
	}
	payload := make([]byte, int(length))
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &Frame{Type: typ, Payload: payload}, nil
}

// encodeSettings 把 SETTINGS 参数编码成帧载荷。每项都是 Identifier(varint) + Value(varint)。
func encodeSettings(settings map[uint64]uint64) []byte {
	var b []byte
	for id, value := range settings {
		b = appendVarint(b, id)
		b = appendVarint(b, value)
	}
	return b
}

// decodeSettings 解析 SETTINGS 帧载荷。
func decodeSettings(payload []byte) (map[uint64]uint64, error) {
	r := make([]byte, len(payload))
	copy(r, payload)
	out := make(map[uint64]uint64)
	for len(r) > 0 {
		id, n, err := readVarintBytes(r)
		if err != nil {
			return nil, err
		}
		r = r[n:]
		value, n, err := readVarintBytes(r)
		if err != nil {
			return nil, err
		}
		r = r[n:]
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("%w: duplicate SETTING 0x%x", ErrBadFrame, id)
		}
		out[id] = value
	}
	return out, nil
}

// encodeGoAway 编码 GOAWAY 帧载荷（单个 varint：最后处理的流 ID）。
func encodeGoAway(lastStreamID uint64) []byte {
	return appendVarint(nil, lastStreamID)
}

// decodeGoAway 解析 GOAWAY 帧载荷；要求恰好一个 varint。
func decodeGoAway(payload []byte) (uint64, error) {
	v, n, err := readVarintBytes(payload)
	if err != nil {
		return 0, err
	}
	if n != len(payload) {
		return 0, fmt.Errorf("%w: trailing bytes in GOAWAY", ErrBadFrame)
	}
	return v, nil
}

// readVarintBytes 从字节切片头部读取一个 varint，返回 (值, 消耗字节数)。
func readVarintBytes(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0] & 0x3f)
	for _, x := range b[1:n] {
		v = v<<8 | uint64(x)
	}
	if n == 8 && v > 1<<62-1 {
		return 0, 0, ErrVarintTooLarge
	}
	return v, n, nil
}
