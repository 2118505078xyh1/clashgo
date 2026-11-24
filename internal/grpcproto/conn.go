package grpcproto

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Conn 把一个 gRPC 双向流包装成 net.Conn。
//
// Write：每次调用把 p 封装成一个 gRPC 消息帧写入请求体（客户端 → 服务端）。
// Read：从响应体解帧，把帧载荷当作字节流返回；跨帧边界对调用方透明。
// 两个方向分别由独立的 io.Pipe / 响应体承载，可并发读写（full duplex）。
type Conn struct {
	pw   *io.PipeWriter // 客户端流的写入端
	resp io.ReadCloser  // 服务端流的读取端
	addr string         // 远端地址（用于 net.Addr）

	maxMessageSize int

	// rmu 串行化阻塞的解帧读取；wmu 串行化阻塞的帧写入。
	// mu 只保护下面的短临界区状态，绝不在持有 mu 时做阻塞 I/O。
	rmu sync.Mutex
	wmu sync.Mutex
	mu  sync.Mutex

	rbuf     []byte // 已解帧但尚未交给调用方的字节
	readErr  error  // 读取方向记录的错误（含 io.EOF）
	writeErr error  // 写入方向记录的错误
	closed   bool

	readDeadline  time.Time
	writeDeadline time.Time
	timer         *time.Timer // 截止时触发 closeUnderlying 以唤醒阻塞的 I/O

	closeOnce sync.Once
	done      chan struct{} // Close / 超时 / ctx 取消时关闭
}

var _ net.Conn = (*Conn)(nil)

func newConn(pw *io.PipeWriter, resp io.ReadCloser, addr string) *Conn {
	return &Conn{
		pw:             pw,
		resp:           resp,
		addr:           addr,
		maxMessageSize: DefaultMaxMessageSize,
		done:           make(chan struct{}),
	}
}

// ---------------------------------------------------------------------------
// net.Conn 接口
// ---------------------------------------------------------------------------

// Read 读取服务端流中的字节。它按需解帧，帧边界对调用方不可见。
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		c.mu.Lock()
		if err := checkDeadline(c.readDeadline, "read"); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if err := c.readErr; err != nil {
			c.mu.Unlock()
			return 0, err
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.mu.Unlock()

		// 没有缓冲数据：阻塞解一帧（rmu 保证同时只有一个 goroutine 读流）。
		c.rmu.Lock()
		payload, _, err := readFrame(c.resp, c.maxMessageSize)
		c.rmu.Unlock()

		c.mu.Lock()
		if err != nil {
			// 看门狗会在截止时关闭底层流以唤醒阻塞的 Read；此时把
			// 底层「已关闭」错误转换为规范的超时 net.Error。
			if de := checkDeadline(c.readDeadline, "read"); de != nil {
				err = de
			}
			c.readErr = err
		} else {
			c.rbuf = append(c.rbuf, payload...)
		}
		c.mu.Unlock()
	}
}

// Write 把 p 封装为一个 gRPC 消息帧写入客户端流。
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	if err := checkDeadline(c.writeDeadline, "write"); err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if err := c.writeErr; err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()

	c.wmu.Lock()
	err := writeFrame(c.pw, p, false)
	c.wmu.Unlock()

	if err != nil {
		c.mu.Lock()
		if de := checkDeadline(c.writeDeadline, "write"); de != nil {
			err = de
		}
		c.writeErr = err
		c.mu.Unlock()
		return 0, err
	}
	return len(p), nil
}

// Close 关闭双向流：结束客户端流（相当于 HTTP/2 END_STREAM）并释放响应体。
func (c *Conn) Close() error { c.closeUnderlying(); return nil }

func (c *Conn) LocalAddr() net.Addr  { return streamAddr("grpc:local") }
func (c *Conn) RemoteAddr() net.Addr { return streamAddr(c.addr) }

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.resetTimerLocked()
	c.mu.Unlock()
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.resetTimerLocked()
	c.mu.Unlock()
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.resetTimerLocked()
	c.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------------------
// 内部实现
// ---------------------------------------------------------------------------

func (c *Conn) closeUnderlying() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
			c.timer = nil
		}
		close(c.done)
		c.mu.Unlock()

		// 关闭管道写端会唤醒阻塞的 Write，并向服务端发出流结束信号。
		_ = c.pw.Close()
		_ = c.resp.Close()
	})
}

// resetTimerLocked 依据当前读写截止时间重置看门狗定时器。
// 调用方必须持有 c.mu。
func (c *Conn) resetTimerLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	var earliest time.Time
	if !c.readDeadline.IsZero() {
		earliest = c.readDeadline
	}
	if !c.writeDeadline.IsZero() && (earliest.IsZero() || c.writeDeadline.Before(earliest)) {
		earliest = c.writeDeadline
	}
	if earliest.IsZero() {
		return
	}
	d := time.Until(earliest)
	if d < 0 {
		d = 0
	}
	c.timer = time.AfterFunc(d, c.closeUnderlying)
}

// checkDeadline 在阻塞 I/O 之前检查截止时间是否已经过期。
func checkDeadline(t time.Time, op string) error {
	if !t.IsZero() && !time.Now().Before(t) {
		return &net.OpError{Op: op, Net: "grpc", Err: os.ErrDeadlineExceeded}
	}
	return nil
}

// cancelOn 监听 ctx，取消时关闭本连接；连接先关闭时该 goroutine 退出。
func (c *Conn) cancelOn(ctx <-chan struct{}) {
	go func() {
		select {
		case <-ctx:
			c.closeUnderlying()
		case <-c.done:
		}
	}()
}

type streamAddr string

func (a streamAddr) Network() string { return "grpc" }
func (a streamAddr) String() string  { return string(a) }
