package quicproto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// Hysteria2（简化版）协议头。
//
// 真实 Hysteria2 的认证发生在 QUIC + TLS 1.3 之上（认证信息放在 TLS ALPN /
// HTTP/3 头中），标准库无法实现。这里采用「QUIC-like」传输层上的自定义明文头：
//
//	 0                   1                   2                   3
//	| 'H'                | '2'                | version = 2       | cmd = 0x01    |
//	| authLen = 32       | auth = SHA256(password) [32] ...                    |
//	| saltLen = 16       | salt [16] ...                                      |
//	| bandwidth hint (8, big endian, Mbps)                                    |
//	| target: type(1) + [len(1)+]host + port(2)                                |
//
// 服务端在收到头后回复 1 字节状态：0x00 成功 / 0x01 认证失败。随后双方用
// SHA256(password) 与 salt 经 HKDF-SHA256 派生 AES-256-GCM 会话密钥，开始
// 加密记录流（见 crypto.go）。
const (
	h2Magic           = "H2"
	h2Version    byte = 2
	h2CmdConnect byte = 0x01
	h2SaltLen    byte = 16
	h2OK         byte = 0x00
	h2AuthFail   byte = 0x01
)

// h2Header 是解析后的 Hysteria2 认证头。
type h2Header struct {
	version   byte
	command   byte
	auth      [32]byte
	salt      []byte
	bandwidth uint64
	target    targetAddr
}

// buildHysteria2Header 构造认证头，并返回派生会话密钥所用的 salt。
func buildHysteria2Header(cfg Config, host string, port uint16) ([]byte, []byte, error) {
	if cfg.Password == "" {
		return nil, nil, errors.New("quicproto: hysteria2 requires a password")
	}
	salt, err := randomBytes(int(h2SaltLen))
	if err != nil {
		return nil, nil, err
	}
	auth := authHash(cfg.Password)

	b := make([]byte, 0, 128)
	b = append(b, h2Magic[0], h2Magic[1], h2Version, h2CmdConnect)
	b = append(b, byte(len(auth)))
	b = append(b, auth[:]...)
	b = append(b, byte(len(salt)))
	b = append(b, salt...)
	var bw [8]byte
	binary.BigEndian.PutUint64(bw[:], uint64(cfg.Bandwidth))
	b = append(b, bw[:]...)
	b, err = appendTargetAddr(b, host, port)
	if err != nil {
		return nil, nil, err
	}
	return b, salt, nil
}

// parseHysteria2Header 解析认证头（供简化版服务端 / 测试使用）。
func parseHysteria2Header(b []byte) (h2Header, error) {
	var h h2Header
	if len(b) < 4 || string(b[:2]) != h2Magic {
		return h, errors.New("quicproto: bad hysteria2 magic")
	}
	h.version = b[2]
	h.command = b[3]
	b = b[4:]
	if h.version != h2Version {
		return h, fmt.Errorf("quicproto: unsupported hysteria2 version %d", h.version)
	}
	if h.command != h2CmdConnect {
		return h, fmt.Errorf("quicproto: unsupported hysteria2 command 0x%02x", h.command)
	}
	if len(b) < 1 {
		return h, errors.New("quicproto: missing hysteria2 auth length")
	}
	authLen := int(b[0])
	b = b[1:]
	if authLen != len(h.auth) || len(b) < authLen {
		return h, errors.New("quicproto: invalid hysteria2 auth")
	}
	copy(h.auth[:], b[:authLen])
	b = b[authLen:]
	if len(b) < 1 {
		return h, errors.New("quicproto: missing hysteria2 salt length")
	}
	saltLen := int(b[0])
	b = b[1:]
	if saltLen == 0 || len(b) < saltLen {
		return h, errors.New("quicproto: invalid hysteria2 salt")
	}
	h.salt = append([]byte(nil), b[:saltLen]...)
	b = b[saltLen:]
	if len(b) < 8 {
		return h, errors.New("quicproto: missing hysteria2 bandwidth")
	}
	h.bandwidth = binary.BigEndian.Uint64(b[:8])
	b = b[8:]
	target, rest, err := readTargetAddr(b)
	if err != nil {
		return h, err
	}
	if len(rest) != 0 {
		return h, errors.New("quicproto: trailing bytes in hysteria2 header")
	}
	h.target = target
	return h, nil
}

// h2SessionAEAD 从密码哈希与 salt 派生双向会话密钥（AES-256-GCM）。
func h2SessionAEAD(auth [32]byte, salt []byte) (c2s, s2c cipher.AEAD, err error) {
	a, err := deriveAEAD(auth[:], salt, []byte("hysteria2-client-to-server"))
	if err != nil {
		return nil, nil, err
	}
	b, err := deriveAEAD(auth[:], salt, []byte("hysteria2-server-to-client"))
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}
