package wgproto

import (
	"encoding/binary"
	"math/bits"
)

// chacha20Block 生成 RFC 8439 定义的一个 64 字节 ChaCha20 块。
// nonce 必须是 12 字节，counter 是 32 位块计数器。
func chacha20Block(key *[32]byte, counter uint32, nonce []byte, out *[64]byte) {
	const (
		c0 = 0x61707865 // "expa"
		c1 = 0x3320646e // "nd 3"
		c2 = 0x79622d32 // "2-by"
		c3 = 0x6b206574 // "te k"
	)
	var s [16]uint32
	s[0], s[1], s[2], s[3] = c0, c1, c2, c3
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:4])
	s[14] = binary.LittleEndian.Uint32(nonce[4:8])
	s[15] = binary.LittleEndian.Uint32(nonce[8:12])

	work := s
	for r := 0; r < 10; r++ {
		chacha20QR(&work, 0, 4, 8, 12)
		chacha20QR(&work, 1, 5, 9, 13)
		chacha20QR(&work, 2, 6, 10, 14)
		chacha20QR(&work, 3, 7, 11, 15)
		chacha20QR(&work, 0, 5, 10, 15)
		chacha20QR(&work, 1, 6, 11, 12)
		chacha20QR(&work, 2, 7, 8, 13)
		chacha20QR(&work, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], work[i]+s[i])
	}
}

func chacha20QR(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = bits.RotateLeft32(s[d], 16)
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = bits.RotateLeft32(s[b], 12)
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = bits.RotateLeft32(s[d], 8)
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = bits.RotateLeft32(s[b], 7)
}

// chacha20XOR 用从 counter 开始的密钥流对 dst 做 XOR；src 与 dst 可相同。
func chacha20XOR(dst, src []byte, key *[32]byte, counter uint32, nonce []byte) {
	var block [64]byte
	for len(src) > 0 {
		chacha20Block(key, counter, nonce, &block)
		n := len(src)
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ block[i]
		}
		dst, src = dst[n:], src[n:]
		counter++
	}
}
