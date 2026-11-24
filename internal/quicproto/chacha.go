package quicproto

// Pure standard-library ChaCha20-Poly1305 (RFC 8439) and the ChaCha20-based
// QUIC header protection of RFC 9001 §5.4.4.
//
// The Go standard library intentionally does not expose crypto/chacha20poly1305
// (it lives in golang.org/x/crypto), so this file implements the primitives
// directly with crypto/cipher's AEAD interface, crypto/subtle and math/big.
// No external modules are imported.

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
)

// ChaCha20 constants: the ASCII string "expand 32-byte k" as LE words.
const (
	chachaC0 uint32 = 0x61707865
	chachaC1 uint32 = 0x3320646e
	chachaC2 uint32 = 0x79622d32
	chachaC3 uint32 = 0x6b206574

	chachaBlockSize = 64
	chachaKeySize   = 32
	chachaNonceSize = 12
	chachaTagSize   = 16
)

// chacha20 is the RFC 8439 §2.3 block function with a 96-bit (12-byte) nonce
// and a 32-bit block counter.
type chacha20 struct {
	key [8]uint32
}

func newChaCha20(key []byte) (*chacha20, error) {
	if len(key) != chachaKeySize {
		return nil, errors.New("quicproto: chacha20: key must be 32 bytes")
	}
	var c chacha20
	for i := 0; i < 8; i++ {
		c.key[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	return &c, nil
}

func chachaRotl(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

func chachaQuarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = chachaRotl(s[d], 16)
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = chachaRotl(s[b], 12)
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = chachaRotl(s[d], 8)
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = chachaRotl(s[b], 7)
}

// block returns one 64-byte keystream block for the given counter+nonce.
func (c *chacha20) block(counter uint32, nonce []byte) [chachaBlockSize]byte {
	if len(nonce) != chachaNonceSize {
		panic("quicproto: chacha20: nonce must be 12 bytes")
	}
	s := [16]uint32{
		chachaC0, chachaC1, chachaC2, chachaC3,
		c.key[0], c.key[1], c.key[2], c.key[3],
		c.key[4], c.key[5], c.key[6], c.key[7],
		counter,
		binary.LittleEndian.Uint32(nonce[0:4]),
		binary.LittleEndian.Uint32(nonce[4:8]),
		binary.LittleEndian.Uint32(nonce[8:12]),
	}
	initial := s
	for i := 0; i < 10; i++ { // 20 rounds = 10 column/diagonal pairs
		chachaQuarterRound(&s, 0, 4, 8, 12)
		chachaQuarterRound(&s, 1, 5, 9, 13)
		chachaQuarterRound(&s, 2, 6, 10, 14)
		chachaQuarterRound(&s, 3, 7, 11, 15)
		chachaQuarterRound(&s, 0, 5, 10, 15)
		chachaQuarterRound(&s, 1, 6, 11, 12)
		chachaQuarterRound(&s, 2, 7, 8, 13)
		chachaQuarterRound(&s, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		s[i] += initial[i]
	}
	var out [chachaBlockSize]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], s[i])
	}
	return out
}

// xorKeyStream XORs src with the keystream beginning at counter 1 (counter 0
// is reserved for the one-time Poly1305 key in the AEAD construction).
func (c *chacha20) xorKeyStream(dst, src []byte, nonce []byte) {
	counter := uint32(1)
	for len(src) > 0 {
		ks := c.block(counter, nonce)
		n := len(src)
		if n > chachaBlockSize {
			n = chachaBlockSize
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ ks[i]
		}
		src = src[n:]
		dst = dst[n:]
		counter++
	}
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 8439 §2.5)
// ---------------------------------------------------------------------------

var (
	poly1305P    = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	poly1305Mask = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
)

// reverseBytes converts a little-endian byte representation to big-endian so
// that math/big (which expects big-endian) can be used without manual limbs.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// poly1305 computes the 16-byte RFC 8439 tag of msg under a 32-byte one-time
// key. math/big keeps the implementation short and, more importantly, correct;
// the MAC is not comparison-revealing because the key is single-use.
func poly1305(tag []byte, msg []byte, key []byte) {
	if len(key) != 32 {
		panic("quicproto: poly1305: key must be 32 bytes")
	}
	var rBytes [16]byte
	copy(rBytes[:], key[:16])
	rBytes[3] &= 15
	rBytes[7] &= 15
	rBytes[11] &= 15
	rBytes[15] &= 15
	rBytes[4] &= 252
	rBytes[8] &= 252
	rBytes[12] &= 252
	r := new(big.Int).SetBytes(reverseBytes(rBytes[:]))
	s := new(big.Int).SetBytes(reverseBytes(key[16:32]))

	acc := new(big.Int)
	n := new(big.Int)
	var block [17]byte
	for len(msg) > 0 {
		chunk := msg
		if len(chunk) > 16 {
			chunk = chunk[:16]
		}
		copy(block[:], chunk)
		block[len(chunk)] = 1 // high 0x01 sentinel
		for i := len(chunk) + 1; i < len(block); i++ {
			block[i] = 0
		}
		n.SetBytes(reverseBytes(block[:]))
		acc.Add(acc, n)
		acc.Mul(acc, r)
		acc.Mod(acc, poly1305P)
		msg = msg[len(chunk):]
	}
	acc.Add(acc, s)
	acc.And(acc, poly1305Mask) // keep the low 128 bits
	le := reverseBytes(acc.Bytes())
	for i := 0; i < chachaTagSize; i++ {
		if i < len(le) {
			tag[i] = le[i]
		} else {
			tag[i] = 0
		}
	}
}

// ---------------------------------------------------------------------------
// AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
// ---------------------------------------------------------------------------

type chacha20poly1305 struct {
	chacha *chacha20
}

func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	c, err := newChaCha20(key)
	if err != nil {
		return nil, err
	}
	return &chacha20poly1305{chacha: c}, nil
}

func (*chacha20poly1305) NonceSize() int { return chachaNonceSize }
func (*chacha20poly1305) Overhead() int  { return chachaTagSize }

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}

func pad16(b []byte) []byte {
	if rem := len(b) % 16; rem != 0 {
		out := make([]byte, len(b)+(16-rem))
		copy(out, b)
		return out
	}
	return b
}

func (a *chacha20poly1305) computeTag(nonce, ciphertext, aad []byte) [chachaTagSize]byte {
	otkBlock := a.chacha.block(0, nonce) // counter 0 -> one-time Poly1305 key
	var otk [32]byte
	copy(otk[:], otkBlock[:32])

	macData := make([]byte, 0, len(pad16(aad))+len(pad16(ciphertext))+16)
	macData = append(macData, pad16(aad)...)
	macData = append(macData, pad16(ciphertext)...)
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(len(ciphertext)))
	macData = append(macData, lens[:]...)

	var tag [chachaTagSize]byte
	poly1305(tag[:], macData, otk[:])
	return tag
}

func (a *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chachaNonceSize {
		panic("quicproto: chacha20poly1305: nonce must be 12 bytes")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+chachaTagSize)
	a.chacha.xorKeyStream(out[:len(plaintext)], plaintext, nonce)
	tag := a.computeTag(nonce, out[:len(plaintext)], additionalData)
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (a *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chachaNonceSize {
		return nil, errors.New("quicproto: chacha20poly1305: nonce must be 12 bytes")
	}
	if len(ciphertext) < chachaTagSize {
		return nil, errors.New("quicproto: chacha20poly1305: ciphertext too short")
	}
	ct := ciphertext[:len(ciphertext)-chachaTagSize]
	expected := a.computeTag(nonce, ct, additionalData)
	if subtle.ConstantTimeCompare(expected[:], ciphertext[len(ct):]) != 1 {
		return nil, errors.New("quicproto: chacha20poly1305: message authentication failed")
	}
	ret, out := sliceForAppend(dst, len(ct))
	a.chacha.xorKeyStream(out, ct, nonce)
	return ret, nil
}

// ---------------------------------------------------------------------------
// QUIC ChaCha20 header protection (RFC 9001 §5.4.4)
// ---------------------------------------------------------------------------

// chacha20HPMask computes the 5-byte header-protection mask. RFC 9001 §5.4.4
// interprets the 16-byte ciphertext sample as: counter = sample[0:4] (LE),
// nonce = sample[4:16]; the first 5 bytes of the ChaCha20 block are the mask.
func chacha20HPMask(hpKey, sample []byte) ([5]byte, error) {
	var mask [5]byte
	if len(hpKey) != chachaKeySize || len(sample) < 16 {
		return mask, errors.New("quicproto: chacha20 hp: need 32-byte key and 16-byte sample")
	}
	c, err := newChaCha20(hpKey)
	if err != nil {
		return mask, err
	}
	counter := binary.LittleEndian.Uint32(sample[0:4])
	block := c.block(counter, sample[4:16])
	copy(mask[:], block[:5])
	return mask, nil
}

// NewChaCha20Poly1305 导出 ChaCha20-Poly1305 AEAD 构造，供同项目其它包复用
// （如 Reality 的 TLS 1.3 ChaCha20 套件）。
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	return newChaCha20Poly1305(key)
}
