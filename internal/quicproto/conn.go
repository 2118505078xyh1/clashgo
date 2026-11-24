package quicproto

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Config 是出站连接的配置。
//
// 字段与常见 Hysteria2 / TUIC 配置保持兼容，便于接入现有配置体系。注意
// ServerName / SkipVerify 在本包中不参与真正的 TLS 证书校验（本包不实现 TLS），
// 仅作为扩展字段保留：ServerName 可填入头部的可选 SNI 名称占位，SkipVerify
// 仅用于表达「不做证书校验」的既有配置语义。Bandwidth 作为带宽提示写入
// Hysteria2 头（不参与真实拥塞控制）。
type Config struct {
	Server     string // 服务端 UDP 地址，例如 "example.com:443"
	Password   string // Hysteria2 密码；TUIC 可留空（此时用 Token）
	UUID       string // TUIC UUID
	Token      string // TUIC token
	ServerName string // 保留字段： TLS SNI 名称占位（本包无真实 TLS）
	SkipVerify bool   // 保留字段：无证书校验
	Bandwidth  int    // 带宽提示（Mbps），不参与真实拥塞控制
}

// Conn 是 Hysteria2 / TUIC 出站连接。
//
// 它实现 net.Conn：Write 写入经 AEAD 加密的代理载荷，Read 读取服务端返回的
// 解密载荷。底层是 dialReliable 建立的最小可靠 UDP 流。
type Conn struct {
	rc       *reliableConn
	stream   *aeadStream
	protocol string
	target   string
}

// ---------------------------------------------------------------------------
// 公共 API
// ---------------------------------------------------------------------------

// DialHysteria2 建立到服务端的 Hysteria2（简化版）出站连接。
// host/port 是要通过代理访问的目标地址，cfg.Server 是代理服务端 UDP 地址。
func DialHysteria2(ctx context.Context, cfg Config, host string, port uint16) (net.Conn, error) {
	return dial(ctx, cfg, host, port, "hysteria2")
}

// DialTUIC 建立到服务端的 TUIC（简化版）出站连接。
// host/port 是要通过代理访问的目标地址，cfg.Server 是代理服务端 UDP 地址。
func DialTUIC(ctx context.Context, cfg Config, host string, port uint16) (net.Conn, error) {
	return dial(ctx, cfg, host, port, "tuic")
}

type handshakeSpec struct {
	build func(Config, string, uint16) ([]byte, []byte, error)
	keys  func([32]byte, []byte) (c2s, s2c cipher.AEAD, err error)
	ok    byte
	name  string
}

func dial(ctx context.Context, cfg Config, host string, port uint16, protocol string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.Server == "" {
		return nil, errors.New("quicproto: empty server address")
	}
	if cfg.Bandwidth < 0 {
		return nil, errors.New("quicproto: negative bandwidth")
	}

	var spec handshakeSpec
	switch protocol {
	case "hysteria2":
		spec = handshakeSpec{
			build: buildHysteria2Header,
			keys:  h2SessionAEAD,
			ok:    h2OK,
			name:  "hysteria2",
		}
	case "tuic":
		spec = handshakeSpec{
			build: buildTUICHeader,
			keys:  tuicSessionAEAD,
			ok:    tuicOK,
			name:  "tuic",
		}
	default:
		return nil, fmt.Errorf("quicproto: unknown protocol %q", protocol)
	}

	header, salt, err := spec.build(cfg, host, port)
	if err != nil {
		return nil, err
	}
	secret := authHash(credentialFor(cfg, protocol))

	rc, err := dialReliable(ctx, cfg.Server)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		rc.Close()
		return nil, err
	}

	// 握手阶段设置截止时间：优先使用 ctx 的 deadline，否则给 5 秒。
	if dl, ok := effectiveDeadline(ctx); ok {
		_ = rc.SetDeadline(dl)
	}
	if _, err := writeFull(rc, header); err != nil {
		return fail(fmt.Errorf("quicproto: write %s header: %w", spec.name, err))
	}
	var status [1]byte
	if _, err := io.ReadFull(rc, status[:]); err != nil {
		return fail(fmt.Errorf("quicproto: read %s auth status: %w", spec.name, err))
	}
	_ = rc.SetDeadline(time.Time{})
	if status[0] != spec.ok {
		if status[0] == h2AuthFail || status[0] == tuicAuthFail {
			return fail(errors.New("quicproto: authentication failed"))
		}
		return fail(fmt.Errorf("quicproto: unexpected %s status 0x%02x", spec.name, status[0]))
	}

	c2s, s2c, err := spec.keys(secret, salt)
	if err != nil {
		return fail(err)
	}

	c := &Conn{
		rc:       rc,
		stream:   newAEADStream(rc, s2c, c2s),
		protocol: spec.name,
		target:   net.JoinHostPort(host, fmt.Sprintf("%d", port)),
	}
	return c, nil
}

// credentialFor 返回用于派生会话密钥的共享秘密。
// Hysteria2 用密码，TUIC 用 token（留空时退化为密码）。
func credentialFor(cfg Config, protocol string) string {
	if protocol == "tuic" {
		if cfg.Token != "" {
			return cfg.Token
		}
		return cfg.Password
	}
	return cfg.Password
}

func effectiveDeadline(ctx context.Context) (time.Time, bool) {
	if dl, ok := ctx.Deadline(); ok {
		return dl, true
	}
	return time.Now().Add(handshakeTimeout), true
}

// ---------------------------------------------------------------------------
// net.Conn 接口
// ---------------------------------------------------------------------------

func (c *Conn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.stream.Write(p) }

func (c *Conn) Close() error { return c.rc.Close() }

func (c *Conn) LocalAddr() net.Addr  { return c.rc.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.rc.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error      { return c.rc.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.rc.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.rc.SetWriteDeadline(t) }

// Target 返回通过该连接访问的目标地址（host:port）。
func (c *Conn) Target() string { return c.target }

// Protocol 返回协议名（"hysteria2" 或 "tuic"）。
func (c *Conn) Protocol() string { return c.protocol }

var _ net.Conn = (*Conn)(nil)
