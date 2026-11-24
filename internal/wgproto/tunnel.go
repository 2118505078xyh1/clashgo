package wgproto

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

const (
	maxSendCounter      = (1 << 64) - 1
	handshakeAttempts   = 5
	handshakeTimeout    = 5 * time.Second
	rekeyInterval       = 2 * time.Minute
	maintenanceTick     = 15 * time.Second
	readChannelSize     = 64
	responseChannelSize = 8
)

var (
	errNotReady         = errors.New("wgproto: tunnel is not established; call Start first")
	errCounterExhausted = errors.New("wgproto: send counter exhausted, rekey required")
)

// Tunnel 是一个 WireGuard 发起方会话。它实现 net.PacketConn：
// WriteTo 写入的是内层 IP 包（会被加密封装为 WireGuard transport data），
// ReadFrom 返回解密后的内层 IP 包。
//
// 本包不实现 TUN 设备或 TCP 栈，上层自行处理 IP/TCP。
type Tunnel struct {
	cfg        *parsedConfig
	udp        *net.UDPConn
	remote     *net.UDPAddr
	localIndex uint32

	mu            sync.Mutex
	hs            *noiseHandshake
	sendKey       [blake2sSize]byte
	recvKey       [blake2sSize]byte
	sendAEAD      cipher.AEAD
	recvAEAD      cipher.AEAD
	sendCounter   uint64
	recvCounter   uint64
	replayBits    uint64
	sessionOK     bool
	lastHandshake time.Time
	lastActivity  time.Time

	responseCh chan []byte
	readCh     chan []byte
	done       chan struct{}
	closeOnce  sync.Once

	deadlineMu   sync.Mutex
	readDeadline time.Time

	err error
}

// New 创建隧道对象并绑定本地 UDP 端口；此时尚未握手。
func New(cfg Config) (*Tunnel, error) {
	p, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	idx, err := randomIndex()
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	t := &Tunnel{
		cfg:        p,
		udp:        udp,
		remote:     p.endpoint,
		localIndex: idx,
		responseCh: make(chan []byte, responseChannelSize),
		readCh:     make(chan []byte, readChannelSize),
		done:       make(chan struct{}),
	}
	return t, nil
}

func randomIndex() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v, nil
}

// Start 完成一次握手并启动接收、保活、重协商循环。
func (t *Tunnel) Start() error {
	go t.readLoop()
	if err := t.handshake(context.Background()); err != nil {
		_ = t.Close()
		return err
	}
	go t.keepaliveLoop()
	go t.maintenanceLoop()
	return nil
}

// StartContext 与 Start 相同，但握手过程可被 ctx 取消。
func (t *Tunnel) StartContext(ctx context.Context) error {
	go t.readLoop()
	if err := t.handshake(ctx); err != nil {
		_ = t.Close()
		return err
	}
	go t.keepaliveLoop()
	go t.maintenanceLoop()
	return nil
}

func (t *Tunnel) handshake(ctx context.Context) error {
	for attempt := 0; attempt < handshakeAttempts; attempt++ {
		select {
		case <-t.done:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		idx, err := randomIndex()
		if err != nil {
			return err
		}
		hs, err := newNoiseHandshake(t.cfg.peerPublicKey[:], idx)
		if err != nil {
			return err
		}
		initMsg, err := hs.createInitiation(t.cfg.privateKey, t.cfg.peerPublicKey[:])
		if err != nil {
			return err
		}
		t.mu.Lock()
		t.hs = hs
		t.mu.Unlock()

		if _, err := t.udp.WriteToUDP(initMsg, t.remote); err != nil {
			return err
		}

		timer := time.NewTimer(handshakeTimeout)
		select {
		case resp := <-t.responseCh:
			timer.Stop()
			sendKey, recvKey, err := hs.consumeResponse(resp, t.cfg.privateKey)
			if err != nil {
				continue // 忽略伪造/过期响应，重试
			}
			sendAEAD, err := newChaCha20Poly1305(sendKey[:])
			if err != nil {
				return err
			}
			recvAEAD, err := newChaCha20Poly1305(recvKey[:])
			if err != nil {
				return err
			}
			t.mu.Lock()
			t.localIndex = idx
			t.sendKey, t.recvKey = sendKey, recvKey
			t.sendAEAD, t.recvAEAD = sendAEAD, recvAEAD
			t.sendCounter, t.recvCounter, t.replayBits = 0, 0, 0
			t.sessionOK = true
			t.lastHandshake = time.Now()
			t.lastActivity = time.Now()
			t.hs = nil
			t.mu.Unlock()
			return nil
		case <-timer.C:
			// 超时重试
		case <-t.done:
			timer.Stop()
			return net.ErrClosed
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	return errors.New("wgproto: handshake timed out")
}

func (t *Tunnel) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := t.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			t.mu.Lock()
			if t.err == nil {
				t.err = err
			}
			t.mu.Unlock()
			return
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		if len(msg) < 4 {
			continue
		}
		switch binary.LittleEndian.Uint32(msg[0:4]) {
		case messageResponseType:
			select {
			case t.responseCh <- msg:
			default: // 响应队列满则丢弃
			}
		case messageTransportType:
			t.handleTransport(msg)
		}
	}
}

// replayOK 实现 64 包滑动窗口重放过滤。调用方持有 t.mu。
func (t *Tunnel) replayOK(counter uint64) bool {
	if counter == t.recvCounter {
		return false
	}
	if counter < t.recvCounter {
		diff := t.recvCounter - counter
		if diff > 63 {
			return false
		}
		bit := uint64(1) << diff
		if t.replayBits&bit != 0 {
			return false
		}
		t.replayBits |= bit
		return true
	}
	shift := counter - t.recvCounter
	if shift >= 64 {
		t.replayBits = 0
	} else {
		t.replayBits <<= shift
	}
	t.recvCounter = counter
	t.replayBits |= 1
	return true
}

func (t *Tunnel) handleTransport(msg []byte) {
	if len(msg) < transportHeaderSize+aeadTagSize {
		return
	}
	receiver := binary.LittleEndian.Uint32(msg[4:8])
	counter := binary.LittleEndian.Uint64(msg[8:16])

	t.mu.Lock()
	if !t.sessionOK || receiver != t.localIndex || t.recvAEAD == nil {
		t.mu.Unlock()
		return
	}
	if !t.replayOK(counter) {
		t.mu.Unlock()
		return
	}
	aead := t.recvAEAD
	nonce := makeNonce(counter)
	plain, err := aead.Open(nil, nonce[:], msg[transportHeaderSize:], nil)
	if err == nil {
		t.lastActivity = time.Now()
	}
	t.mu.Unlock()
	if err != nil || len(plain) == 0 {
		return // 空载荷是 keepalive，不向上层交付
	}

	select {
	case t.readCh <- plain:
	default:
		// 队列满时丢弃最老的一个包，保证新包及时交付
		select {
		case <-t.readCh:
		default:
		}
		select {
		case t.readCh <- plain:
		default:
		}
	}
}

func (t *Tunnel) keepaliveLoop() {
	secs := t.cfg.keepalive
	if secs <= 0 {
		return
	}
	interval := time.Duration(secs) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			idle := time.Since(t.lastActivity) >= interval
			t.mu.Unlock()
			if idle {
				_, _ = t.WriteTo(nil, t.remote)
			}
		case <-t.done:
			return
		}
	}
}

func (t *Tunnel) maintenanceLoop() {
	ticker := time.NewTicker(maintenanceTick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.mu.Lock()
			need := !t.sessionOK || time.Since(t.lastHandshake) > rekeyInterval
			t.mu.Unlock()
			if need {
				ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout*handshakeAttempts)
				_ = t.handshake(ctx)
				cancel()
			}
		case <-t.done:
			return
		}
	}
}

// WriteTo 发送一个内层 IP 包。addr 被忽略（隧道只有一个对端）。
func (t *Tunnel) WriteTo(b []byte, addr net.Addr) (int, error) {
	t.mu.Lock()
	if !t.sessionOK || t.sendAEAD == nil {
		t.mu.Unlock()
		return 0, errNotReady
	}
	counter := t.sendCounter
	if counter >= maxSendCounter {
		t.mu.Unlock()
		return 0, errCounterExhausted
	}
	t.sendCounter++
	aead := t.sendAEAD
	localIndex := t.localIndex
	t.lastActivity = time.Now()
	t.mu.Unlock()

	nonce := makeNonce(counter)
	sealed := aead.Seal(nil, nonce[:], b, nil)
	packet := make([]byte, transportHeaderSize+len(sealed))
	binary.LittleEndian.PutUint32(packet[0:4], messageTransportType)
	binary.LittleEndian.PutUint32(packet[4:8], localIndex)
	binary.LittleEndian.PutUint64(packet[8:16], counter)
	copy(packet[transportHeaderSize:], sealed)
	if _, err := t.udp.WriteToUDP(packet, t.remote); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom 读取一个解密后的内层 IP 包。
func (t *Tunnel) ReadFrom(b []byte) (int, net.Addr, error) {
	t.deadlineMu.Lock()
	deadline := t.readDeadline
	t.deadlineMu.Unlock()

	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case p := <-t.readCh:
		return copy(b, p), t.remote, nil
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case <-t.done:
		return 0, nil, net.ErrClosed
	}
}

func (t *Tunnel) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.done)
		err = t.udp.Close()
	})
	return err
}

func (t *Tunnel) LocalAddr() net.Addr  { return t.udp.LocalAddr() }
func (t *Tunnel) RemoteAddr() net.Addr { return t.remote }

func (t *Tunnel) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

func (t *Tunnel) SetReadDeadline(deadline time.Time) error {
	t.deadlineMu.Lock()
	t.readDeadline = deadline
	t.deadlineMu.Unlock()
	return nil
}

func (t *Tunnel) SetWriteDeadline(deadline time.Time) error {
	return t.udp.SetWriteDeadline(deadline)
}

// AllowedIPs 返回配置中解析后的允许 IP 段。
func (t *Tunnel) AllowedIPs() []*net.IPNet { return t.cfg.allowedIPs }
