package grpcproto

// HTTP/2 帧层（RFC 7540 Section 4、6），仅处理本客户端需要的帧类型。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// FrameType 是 HTTP/2 帧类型。
type FrameType byte

const (
	FrameData         FrameType = 0x0
	FrameHeaders      FrameType = 0x1
	FrameRSTStream    FrameType = 0x3
	FrameContinuation FrameType = 0x9
	FrameSettings     FrameType = 0x4
	FramePing         FrameType = 0x6
	FrameGoAway       FrameType = 0x7
	FrameWindowUpdate FrameType = 0x8
)

// 帧标志（不同帧类型复用同一位，含义不同）。
const (
	FlagEndStream  byte = 0x01 // DATA / HEADERS
	FlagAck        byte = 0x01 // SETTINGS / PING
	FlagEndHeaders byte = 0x04 // HEADERS
	FlagPadded     byte = 0x08 // DATA / HEADERS
	FlagPriority   byte = 0x20 // HEADERS
)

const (
	frameHeaderLen = 9
	// maxH2FramePayload 是接收帧载荷的硬上限（16 MiB），防止恶意长度导致巨量分配。
	maxH2FramePayload = 16 << 20
)

// Frame 是一个 HTTP/2 帧。StreamID 为 0 表示连接级帧。
type Frame struct {
	Type     FrameType
	Flags    byte
	StreamID uint32
	Payload  []byte
}

// writeFrameBinary 把帧序列化到 w。调用方负责串行化对 w 的写入。
func writeFrameBinary(w io.Writer, f Frame) error {
	if len(f.Payload) > 0xffffff {
		return fmt.Errorf("h2: frame payload too large: %d", len(f.Payload))
	}
	var hdr [frameHeaderLen]byte
	hdr[0] = byte(len(f.Payload) >> 16)
	hdr[1] = byte(len(f.Payload) >> 8)
	hdr[2] = byte(len(f.Payload))
	hdr[3] = byte(f.Type)
	hdr[4] = f.Flags
	binary.BigEndian.PutUint32(hdr[5:], f.StreamID&0x7fffffff)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

// readFrameBinary 从 r 读取一个完整帧。
func readFrameBinary(r io.Reader, maxPayload int) (Frame, error) {
	if maxPayload <= 0 || maxPayload > maxH2FramePayload {
		maxPayload = maxH2FramePayload
	}
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if n > maxPayload {
		return Frame{}, fmt.Errorf("h2: frame payload %d exceeds limit %d", n, maxPayload)
	}
	f := Frame{
		Type:     FrameType(hdr[3]),
		Flags:    hdr[4],
		StreamID: binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff,
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// frameData 返回去掉 PADDED / PRIORITY 前缀和尾部填充后的实际载荷。
func frameData(f Frame) ([]byte, error) {
	p := f.Payload
	if f.Flags&FlagPadded != 0 {
		if len(p) < 1 {
			return nil, errors.New("h2: padded frame missing pad length")
		}
		pad := int(p[0])
		p = p[1:]
		if pad > len(p) {
			return nil, errors.New("h2: invalid pad length")
		}
		p = p[:len(p)-pad]
	}
	if f.Type == FrameHeaders && f.Flags&FlagPriority != 0 {
		if len(p) < 5 {
			return nil, errors.New("h2: priority frame too short")
		}
		p = p[5:]
	}
	return p, nil
}

// SETTINGS 参数 ID。
const (
	settingHeaderTableSize      uint16 = 0x1
	settingEnablePush           uint16 = 0x2
	settingMaxConcurrentStreams uint16 = 0x3
	settingInitialWindowSize    uint16 = 0x4
	settingMaxFrameSize         uint16 = 0x5
	settingMaxHeaderListSize    uint16 = 0x6
)

// Setting 是一个 SETTINGS 条目。
type Setting struct {
	ID    uint16
	Value uint32
}

// newSettingsFrame 构造一个 SETTINGS 帧；ack 为真时为空载荷 + ACK 标志。
func newSettingsFrame(ack bool, settings ...Setting) Frame {
	f := Frame{Type: FrameSettings}
	if ack {
		f.Flags = FlagAck
		return f
	}
	for _, s := range settings {
		var b [6]byte
		binary.BigEndian.PutUint16(b[0:], s.ID)
		binary.BigEndian.PutUint32(b[2:], s.Value)
		f.Payload = append(f.Payload, b[:]...)
	}
	return f
}

// parseSettings 解析 SETTINGS 帧载荷。
func parseSettings(payload []byte) ([]Setting, error) {
	if len(payload)%6 != 0 {
		return nil, errors.New("h2: SETTINGS payload not multiple of 6")
	}
	out := make([]Setting, 0, len(payload)/6)
	for i := 0; i < len(payload); i += 6 {
		out = append(out, Setting{
			ID:    binary.BigEndian.Uint16(payload[i:]),
			Value: binary.BigEndian.Uint32(payload[i+2:]),
		})
	}
	return out, nil
}

func newHeadersFrame(streamID uint32, block []byte, endStream bool) Frame {
	f := Frame{Type: FrameHeaders, StreamID: streamID, Flags: FlagEndHeaders, Payload: block}
	if endStream {
		f.Flags |= FlagEndStream
	}
	return f
}

func newDataFrame(streamID uint32, data []byte, endStream bool) Frame {
	f := Frame{Type: FrameData, StreamID: streamID, Payload: data}
	if endStream {
		f.Flags |= FlagEndStream
	}
	return f
}

func newWindowUpdateFrame(streamID uint32, increment uint32) Frame {
	f := Frame{Type: FrameWindowUpdate, StreamID: streamID, Payload: make([]byte, 4)}
	binary.BigEndian.PutUint32(f.Payload, increment&0x7fffffff)
	return f
}

func parseWindowUpdate(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, errors.New("h2: WINDOW_UPDATE payload not 4 bytes")
	}
	return binary.BigEndian.Uint32(payload) & 0x7fffffff, nil
}

func newPingFrame(data [8]byte, ack bool) Frame {
	f := Frame{Type: FramePing, Payload: data[:]}
	if ack {
		f.Flags = FlagAck
	}
	return f
}

func newRSTStreamFrame(streamID, code uint32) Frame {
	f := Frame{Type: FrameRSTStream, StreamID: streamID, Payload: make([]byte, 4)}
	binary.BigEndian.PutUint32(f.Payload, code)
	return f
}
