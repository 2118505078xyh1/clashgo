package quicproto

import (
	"context"
	"fmt"
	"net"
)

// Connection 是通用的 QUIC 连接接口，供上层协议（HTTP/3、Hysteria2 等）使用。
// QUIC 的数据在流上传输，因此连接本身只需提供开关流与关闭能力。
type Connection interface {
	OpenStream() (Stream, error)    // 打开一条新的双向流
	OpenUniStream() (Stream, error) // 打开一条新的单向流
	Close() error                   // 关闭整个 QUIC 连接

	// DATAGRAM（RFC 9000 §19.4）：握手完成后可用的不可靠数据报。
	SendDatagram(payload []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	// 密钥更新（RFC 9001 §6）：轮换 1-RTT 密钥并翻转 Key Phase 位。
	InitiateKeyUpdate() error

	// RFC 5705 EKM 导出（TUIC v5 认证用）。
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// Stream 是一条 QUIC 流（实现 net.Conn + CloseWrite 半关闭）。
type Stream interface {
	net.Conn
	StreamID() uint64
	CloseWrite() error
}

// Dial 建立通用 QUIC 连接（支持任意 ALPN，如 "h3"/"doq"）。
func Dial(ctx context.Context, address, serverName, alpn string, skipVerify bool) (Connection, error) {
	return dialQUIC(ctx, address, serverName, alpn, skipVerify)
}

// Close 关闭整个 QUIC 连接（暴露内部的 close）。
func (c *quicConnection) Close() error {
	c.close()
	return nil
}

// OpenStream 打开一条新的客户端双向流（stream ID: 0, 4, 8, ...）。
func (c *quicConnection) OpenStream() (Stream, error) { return c.openStream(false) }

// OpenUniStream 打开一条新的客户端单向流（stream ID: 2, 6, 10, ...）。
func (c *quicConnection) OpenUniStream() (Stream, error) { return c.openStream(true) }

func (c *quicConnection) openStream(uni bool) (Stream, error) {
	if !c.handshakeDone {
		return nil, fmt.Errorf("quicproto: handshake not complete")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	start := uint64(0)
	if uni {
		start = 2
	}
	id := start
	for {
		if _, exists := c.streamBuffers[id]; !exists {
			break
		}
		id += 4
	}
	sb := c.getStreamBuffer(id)
	return &QUICStream{conn: c, streamID: id, readBuf: sb}, nil
}

func (s *QUICStream) StreamID() uint64 { return s.streamID }

var _ Connection = (*quicConnection)(nil)
var _ Stream = (*QUICStream)(nil)
