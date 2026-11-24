package quicproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// ---------------------------------------------------------------------------
// 纯标准库密钥派生（HKDF-SHA256, RFC 5869）与认证哈希
// ---------------------------------------------------------------------------

// hkdf 是 HKDF-Extract + HKDF-Expand（RFC 5869）的精简实现。
// 用 HMAC-SHA256 实现，避免依赖 golang.org/x/crypto/hkdf。
func hkdf(secret, salt, info []byte, outLen int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	out := make([]byte, 0, outLen)
	var t []byte
	for i := byte(1); len(out) < outLen; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:outLen]
}

// authHash 计算认证用的密码/令牌哈希（SHA-256）。
// Hysteria2 的真实实现同样使用 SHA-256(password) 作为认证 token；
// 这里沿用该约定，使协议头格式更接近真实协议。
func authHash(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

// deriveAEAD 从共享秘密与盐派生 AEAD。
// info 区分两个方向，避免客户端与服务端使用相同的密钥流。
func deriveAEAD(secret, salt, info []byte) (cipher.AEAD, error) {
	key := hkdf(secret, salt, info, 32) // AES-256
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// randomBytes 返回 n 个密码学安全的随机字节。
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// AEAD 记录层：在可靠字节流之上提供加密与完整性校验
// ---------------------------------------------------------------------------

const (
	maxRecordPlaintext = 16 * 1024 // 单条记录的最大明文长度
	maxRecordSize      = maxRecordPlaintext + 12 + 16 + 2
)

// aeadStream 把一条可靠字节流包装成加密记录流。
//
// 记录格式：
//
//	+--------+--------+-------------+---------------------+
//	| len(2) | nonce(12)| ciphertext | AEAD tag (16)       |
//	+--------+--------+-------------+---------------------+
//
// len 是 nonce+ciphertext+tag 的总长度（big endian）。nonce 每条记录随机生成，
// 因此不需要维护发送计数器，也不存在 nonce 重用问题。
type aeadStream struct {
	conn                net.Conn
	readAEAD, writeAEAD cipher.AEAD

	readMu sync.Mutex
	rbuf   []byte

	writeMu sync.Mutex
}

func newAEADStream(conn net.Conn, readAEAD, writeAEAD cipher.AEAD) *aeadStream {
	return &aeadStream{conn: conn, readAEAD: readAEAD, writeAEAD: writeAEAD}
}

func (s *aeadStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()

	for len(s.rbuf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n < s.readAEAD.NonceSize()+s.readAEAD.Overhead() || n > maxRecordSize {
			return 0, errors.New("quicproto: invalid encrypted record length")
		}
		rec := make([]byte, n)
		if _, err := io.ReadFull(s.conn, rec); err != nil {
			return 0, err
		}
		nonce := rec[:s.readAEAD.NonceSize()]
		plain, err := s.readAEAD.Open(nil, nonce, rec[s.readAEAD.NonceSize():], nil)
		if err != nil {
			return 0, errors.New("quicproto: AEAD authentication failed")
		}
		s.rbuf = plain
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *aeadStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	total := 0
	for total < len(p) {
		chunk := p[total:]
		if len(chunk) > maxRecordPlaintext {
			chunk = chunk[:maxRecordPlaintext]
		}
		nonce, err := randomBytes(s.writeAEAD.NonceSize())
		if err != nil {
			return total, err
		}
		sealed := s.writeAEAD.Seal(nil, nonce, chunk, nil)
		rec := make([]byte, 2+len(nonce)+len(sealed))
		binary.BigEndian.PutUint16(rec[:2], uint16(len(nonce)+len(sealed)))
		copy(rec[2:], nonce)
		copy(rec[2+len(nonce):], sealed)
		if _, err := writeFull(s.conn, rec); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

// writeFull 把 b 完整写入 w（net.Conn.Write 允许短写）。
func writeFull(w io.Writer, b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, err := w.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
