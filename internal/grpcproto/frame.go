package grpcproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// gRPC 消息帧格式（Length-Prefixed-Message）：
//
//	+----------+-----------+------------------+
//	| flag(1B) | length(4) | payload(length)  |
//	+----------+-----------+------------------+
//
// flag 为压缩标志（0 = 未压缩，1 = 已压缩）；length 为 payload 的字节数，
// 使用大端序（big endian）编码。这与 gRPC 官方的 "Message Header" 一致。
const frameHeaderSize = 5

const (
	// DefaultMaxMessageSize 是 Read 端默认接受的单帧最大载荷（4 MiB）。
	DefaultMaxMessageSize = 4 << 20
	// maxFramePayload 是写端允许的单帧载荷硬上限（64 MiB），防止误用 uint32 长度。
	maxFramePayload = 64 << 20
)

var (
	// ErrFrameTooLarge 表示收到的帧长度超过设定上限。
	ErrFrameTooLarge = errors.New("grpcproto: frame too large")
	// ErrBadFrame 表示帧头非法（例如压缩标志不是 0 或 1）。
	ErrBadFrame = errors.New("grpcproto: bad frame header")
)

// writeFrame 将 payload 封装成一个 gRPC 消息帧写入 w。
// compressed 指明载荷是否经过压缩（本包不压缩，恒为 false）。
func writeFrame(w io.Writer, payload []byte, compressed bool) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	var hdr [frameHeaderSize]byte
	if compressed {
		hdr[0] = 1
	}
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))

	// 分两次 Write：先帧头再载荷。调用方（Conn.Write）持有写锁，
	// 不会被其他写者插入，因此在字节流上仍然是一帧。
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrame 从 r 读取并解开一个 gRPC 消息帧。
// maxSize 限制单帧载荷大小，<=0 时使用 DefaultMaxMessageSize。
func readFrame(r io.Reader, maxSize int) (payload []byte, compressed bool, err error) {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	var hdr [frameHeaderSize]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return nil, false, err
	}
	if hdr[0] > 1 {
		return nil, false, fmt.Errorf("%w: compressed flag %d", ErrBadFrame, hdr[0])
	}
	compressed = hdr[0] == 1

	n := binary.BigEndian.Uint32(hdr[1:])
	if uint64(n) > uint64(maxSize) {
		return nil, false, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, maxSize)
	}
	payload = make([]byte, int(n))
	if n > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return nil, false, err
		}
	}
	return payload, compressed, nil
}
