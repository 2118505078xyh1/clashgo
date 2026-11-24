package quicproto

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// TUIC（简化版）协议头。
//
// 真实 TUIC v5 同样基于 QUIC + TLS 1.3，认证由 "authenticate" 与 "connect"
// 两类请求组成（带请求 ID、UUID、token、UDP relay 选项等）。本包把它们压缩
// 为一次握手头，并沿用 UUID / token 这两个核心认证字段：
//
//	 0                   1                   2                   3
//	| 'T'                | 'U'                | version = 5       | cmd = 0x01    |
//	| uuid [16] ...                                                             |
//	| tokenHash = SHA256(token) [32] ...                                        |
//	| saltLen = 16       | salt [16] ...                                       |
//	| target: type(1) + [len(1)+]host + port(2)                                |
//
// 服务端回复 1 字节状态（0x00 成功 / 0x01 认证失败），之后切换到
// HKDF-SHA256 派生的 AES-256-GCM 加密记录流。
const (
	tuicMagic         = "TU"
	tuicVersion  byte = 5
	tuicCmdAuth  byte = 0x01
	tuicSaltLen  byte = 16
	tuicOK       byte = 0x00
	tuicAuthFail byte = 0x01
)

// tuicHeader 是解析后的 TUIC 认证头。
type tuicHeader struct {
	version   byte
	command   byte
	uuid      [16]byte
	tokenHash [32]byte
	salt      []byte
	target    targetAddr
}

// parseUUID 解析规范 UUID 字符串（可含 '-'、'{}'）为 16 字节。
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	cleaned := strings.ReplaceAll(s, "-", "")
	cleaned = strings.TrimPrefix(cleaned, "{")
	cleaned = strings.TrimSuffix(cleaned, "}")
	if len(cleaned) != 32 {
		return out, fmt.Errorf("quicproto: invalid UUID %q: want 32 hex digits", s)
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return out, fmt.Errorf("quicproto: invalid UUID %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

// buildTUICHeader 构造认证头，并返回派生会话密钥所用的 salt。
func buildTUICHeader(cfg Config, host string, port uint16) ([]byte, []byte, error) {
	id, err := parseUUID(cfg.UUID)
	if err != nil {
		return nil, nil, err
	}
	token := cfg.Token
	if token == "" {
		// 许多 TUIC 部署允许 token 为空，此时退化为使用密码。
		token = cfg.Password
	}
	if token == "" {
		return nil, nil, errors.New("quicproto: tuic requires a UUID and token/password")
	}
	tokenHash := authHash(token)
	salt, err := randomBytes(int(tuicSaltLen))
	if err != nil {
		return nil, nil, err
	}

	b := make([]byte, 0, 128)
	b = append(b, tuicMagic[0], tuicMagic[1], tuicVersion, tuicCmdAuth)
	b = append(b, id[:]...)
	b = append(b, tokenHash[:]...)
	b = append(b, byte(len(salt)))
	b = append(b, salt...)
	b, err = appendTargetAddr(b, host, port)
	if err != nil {
		return nil, nil, err
	}
	return b, salt, nil
}

// parseTUICHeader 解析认证头（供简化版服务端 / 测试使用）。
func parseTUICHeader(b []byte) (tuicHeader, error) {
	var h tuicHeader
	if len(b) < 4 || string(b[:2]) != tuicMagic {
		return h, errors.New("quicproto: bad tuic magic")
	}
	h.version = b[2]
	h.command = b[3]
	b = b[4:]
	if h.version != tuicVersion {
		return h, fmt.Errorf("quicproto: unsupported tuic version %d", h.version)
	}
	if h.command != tuicCmdAuth {
		return h, fmt.Errorf("quicproto: unsupported tuic command 0x%02x", h.command)
	}
	if len(b) < len(h.uuid) {
		return h, errors.New("quicproto: truncated tuic uuid")
	}
	copy(h.uuid[:], b[:len(h.uuid)])
	b = b[len(h.uuid):]
	if len(b) < len(h.tokenHash) {
		return h, errors.New("quicproto: truncated tuic token hash")
	}
	copy(h.tokenHash[:], b[:len(h.tokenHash)])
	b = b[len(h.tokenHash):]
	if len(b) < 1 {
		return h, errors.New("quicproto: missing tuic salt length")
	}
	saltLen := int(b[0])
	b = b[1:]
	if saltLen == 0 || len(b) < saltLen {
		return h, errors.New("quicproto: invalid tuic salt")
	}
	h.salt = append([]byte(nil), b[:saltLen]...)
	b = b[saltLen:]
	target, rest, err := readTargetAddr(b)
	if err != nil {
		return h, err
	}
	if len(rest) != 0 {
		return h, errors.New("quicproto: trailing bytes in tuic header")
	}
	h.target = target
	return h, nil
}

// tuicSessionAEAD 从 token 哈希与 salt 派生双向会话密钥（AES-256-GCM）。
func tuicSessionAEAD(tokenHash [32]byte, salt []byte) (c2s, s2c cipher.AEAD, err error) {
	a, err := deriveAEAD(tokenHash[:], salt, []byte("tuic-client-to-server"))
	if err != nil {
		return nil, nil, err
	}
	b, err := deriveAEAD(tokenHash[:], salt, []byte("tuic-server-to-client"))
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}
