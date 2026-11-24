package wgproto

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// chacha20Poly1305 是标准 12 字节 nonce 的 ChaCha20Poly1305 AEAD（RFC 8439）。
// WireGuard 的 Aead(key, counter, ...) 通过 nonce = 4 个零字节 || counter(8 字节小端)
// 映射到本实现。
type chacha20Poly1305 struct {
	key [32]byte
}

var errBadAEADKey = errors.New("wgproto: chacha20poly1305: key must be 32 bytes")

func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errBadAEADKey
	}
	c := &chacha20Poly1305{}
	copy(c.key[:], key)
	return c, nil
}

func (*chacha20Poly1305) NonceSize() int { return 12 }
func (*chacha20Poly1305) Overhead() int  { return 16 }

func (c *chacha20Poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 12 {
		panic("wgproto: chacha20poly1305: incorrect nonce length")
	}
	// 先算 Poly1305 的一次性密钥（counter=0 的块前 32 字节）。
	var polyKey [32]byte
	var firstBlock [64]byte
	chacha20Block(&c.key, 0, nonce, &firstBlock)
	copy(polyKey[:], firstBlock[:32])

	ciphertext := make([]byte, len(plaintext))
	chacha20XOR(ciphertext, plaintext, &c.key, 1, nonce)

	macData := make([]byte, 0,
		len(additionalData)+16+len(plaintext)+16+16)
	macData = append(macData, additionalData...)
	macData = appendZeroPadding(macData, len(additionalData))
	macData = append(macData, ciphertext...)
	macData = appendZeroPadding(macData, len(ciphertext))
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(additionalData)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(ciphertext)))
	macData = append(macData, lens[:]...)

	tag := poly1305Tag(&polyKey, macData)
	out := make([]byte, 0, len(dst)+len(ciphertext)+16)
	out = append(out, dst...)
	out = append(out, ciphertext...)
	out = append(out, tag[:]...)
	return out
}

func (c *chacha20Poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 12 {
		return nil, errors.New("wgproto: chacha20poly1305: incorrect nonce length")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("wgproto: chacha20poly1305: ciphertext too short")
	}
	var polyKey [32]byte
	var firstBlock [64]byte
	chacha20Block(&c.key, 0, nonce, &firstBlock)
	copy(polyKey[:], firstBlock[:32])

	dataLen := len(ciphertext) - 16
	data, tag := ciphertext[:dataLen], ciphertext[dataLen:]

	macData := make([]byte, 0, len(additionalData)+16+dataLen+16+16)
	macData = append(macData, additionalData...)
	macData = appendZeroPadding(macData, len(additionalData))
	macData = append(macData, data...)
	macData = appendZeroPadding(macData, len(data))
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(additionalData)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(data)))
	macData = append(macData, lens[:]...)
	want := poly1305Tag(&polyKey, macData)
	if subtle.ConstantTimeCompare(tag, want[:]) != 1 {
		return nil, errors.New("wgproto: chacha20poly1305: authentication failed")
	}

	plain := make([]byte, len(data))
	chacha20XOR(plain, data, &c.key, 1, nonce)
	out := make([]byte, 0, len(dst)+len(plain))
	out = append(out, dst...)
	out = append(out, plain...)
	return out, nil
}

func appendZeroPadding(b []byte, n int) []byte {
	// 把长度向上取整到 16 的倍数。
	pad := (16 - n%16) % 16
	if pad == 0 {
		return b
	}
	return append(b, make([]byte, pad)...)
}

// makeNonce 按 WireGuard 约定构造 Aead nonce：4 个零字节 + 8 字节小端 counter。
func makeNonce(counter uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}
