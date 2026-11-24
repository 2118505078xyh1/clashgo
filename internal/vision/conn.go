package vision

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
)

// Conn 在明文连接（Reality tls13Conn）之上实现 XTLS Vision 的
// padding/解封装状态机。TLS 握手已经完成，之后写的 VLESS header
// 和读到的响应都要走 Vision 帧。
type Conn struct {
	net.Conn
	userUUID [16]byte

	mu sync.Mutex

	// 写状态
	writeFirst  bool         // 是否还需要写首帧（含 UUID）
	writeDirect bool         // 已切 direct，之后透明透传
	writeBuf    bytes.Buffer // 待写的 Vision 帧缓冲

	// 读状态
	readFirst     bool
	readDirect    bool
	readBuf       bytes.Buffer
	readRemain    int // 当前帧剩余 content+padding 字节
	readContent   int // 当前帧剩余 content 字节
	prefixBytes   int // 首次 Read 前需透传的裸字节数（VLESS 响应头=2）
	prefixHandled bool
	rawConn       net.Conn // 裸 TCP（direct 模式绕过外层 TLS 用）
}

// Wrap 用 Vision 包装一条已完成握手的明文连接。
// conn 是外层 TLS 明文 conn，raw 是其下的裸 TCP（direct 模式用）。
// prefixBytes: 首次 Read 前需从底层透传的裸字节数（VLESS 响应头=2）。
func Wrap(conn, raw net.Conn, uuid [16]byte, prefixBytes int) *Conn {
	return &Conn{
		Conn:        conn,
		rawConn:     raw,
		userUUID:    uuid,
		writeFirst:  true,
		readFirst:   true,
		prefixBytes: prefixBytes,
	}
}

// WriteRaw 绕过 Vision 帧直接写底层（用于 VLESS header —— 它必须出现在
// Vision 帧之前，不能被 Vision padding 包裹）。
func (c *Conn) WriteRaw(p []byte) (int, error) {
	return c.Conn.Write(p)
}

// SetDirect 切换到 direct 模式（当检测到内层 TLS 1.3 时由上层调用）。
func (c *Conn) SetDirect() {
	c.mu.Lock()
	c.writeDirect = true
	c.readDirect = true
	c.mu.Unlock()
}

func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeDirect {
		// direct：内层 TLS 字节直接写裸 TCP（绕过外层 Reality TLS 加密）。
		if c.rawConn != nil {
			return c.rawConn.Write(p)
		}
		return c.Conn.Write(p)
	}
	// 不主动切 direct：内层 TLS 数据继续走 Vision 帧 + 外层 TLS。
	// 服务端若自己切 direct 会通过下行命令帧通知，我们在 Read 里跟随。
	first := c.writeFirst
	frame := buildFrame(p, CommandContinue, c.userUUID[:], first, true)
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	c.writeFirst = false
	return len(p), nil
}

func (c *Conn) Read(p []byte) (int, error) {
	// 首次 Read 前透传 VLESS 响应头等裸字节（它们不在 Vision 帧里）。
	if !c.prefixHandled && c.prefixBytes > 0 {
		buf := make([]byte, c.prefixBytes)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		c.readBuf.Write(buf)
		c.prefixHandled = true
	}
	if c.readDirect {
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}
		if c.rawConn != nil {
			return c.rawConn.Read(p)
		}
		return c.Conn.Read(p)
	}
	// 先消费缓冲
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}
	// 读完当前帧剩余的 content（跳过 padding）
	if c.readRemain > 0 {
		want := c.readRemain
		if want > len(p) {
			want = len(p)
		}
		tmp := make([]byte, want)
		n, err := io.ReadFull(c.Conn, tmp)
		if n > 0 {
			c.readRemain -= n
			if c.readContent > 0 {
				take := n
				if take > c.readContent {
					take = c.readContent
				}
				c.readBuf.Write(tmp[:take])
				c.readContent -= take
			}
		}
		if err != nil {
			return 0, err
		}
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}
	}
	// 读帧头
	need := SubHeaderLen
	if c.readFirst {
		need = HeaderLen
	}
	head := make([]byte, need)
	if _, err := io.ReadFull(c.Conn, head); err != nil {
		return 0, err
	}
	f, ok := parseHeader(head, c.readFirst)
	if !ok {
		return 0, errors.New("vision: short header")
	}
	c.readFirst = false
	// 首帧校验 UUID
	if f.HasUUID && !bytes.Equal(f.UUID[:], c.userUUID[:]) {
		return 0, errors.New("vision: unexpected server UUID")
	}
	if f.Command == CommandDirect {
		// direct 命令帧的 content 是内层 TLS 数据，按长度读出交给上层；
		// padding 丢弃。之后内层 TLS 数据直接从裸 TCP 来。
		c.readDirect = true
		if f.ContentLen > 0 {
			content := make([]byte, f.ContentLen)
			if _, err := io.ReadFull(c.Conn, content); err != nil {
				return 0, err
			}
			c.readBuf.Write(content)
		}
		if f.PaddingLen > 0 {
			if _, err := io.CopyN(io.Discard, c.Conn, int64(f.PaddingLen)); err != nil {
				return 0, err
			}
		}
		// 取出外层 TLS 残留（可能还有未读的内层 TLS 数据），接在 content 后。
		if c.rawConn != nil {
			if tkc, ok := c.Conn.(interface{ TakeReadBuf() []byte }); ok {
				c.readBuf.Write(tkc.TakeReadBuf())
			}
		}
		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}
		if c.rawConn != nil {
			return c.rawConn.Read(p)
		}
		return c.Conn.Read(p)
	}
	// 读 content + padding
	total := f.ContentLen + f.PaddingLen
	if total > 0 {
		buf := make([]byte, total)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		if f.ContentLen > 0 {
			c.readBuf.Write(buf[:f.ContentLen])
		}
	}
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}
	return c.Conn.Read(p)
}
