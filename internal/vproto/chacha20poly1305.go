package vproto

// 本文件是 RFC 8439 / XChaCha20 的纯标准库实现，不依赖 golang.org/x/crypto。
// 提供 ChaCha20 流 cipher、HChaCha20、Poly1305 以及
// AEAD_CHACHA20_POLY1305 / AEAD_XCHACHA20_POLY1305。

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"
)

var (
	chachaConstants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574} // "expand 32-byte k"
	poly1305P       = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	poly1305Mod128  = new(big.Int).Lsh(big.NewInt(1), 128)
	errChachaOpen   = errors.New("chacha20poly1305: message authentication failed")
)

// chachaQR 执行 RFC 8439 第 2.1 节的四分之一轮。
func chachaQR(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = bits.RotateLeft32(x[d], 16)
	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = bits.RotateLeft32(x[b], 12)
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = bits.RotateLeft32(x[d], 8)
	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = bits.RotateLeft32(x[b], 7)
}

// chachaRounds 执行 20 轮（10 个双轮）。
func chachaRounds(x *[16]uint32) {
	for i := 0; i < 10; i++ {
		// 列轮
		chachaQR(x, 0, 4, 8, 12)
		chachaQR(x, 1, 5, 9, 13)
		chachaQR(x, 2, 6, 10, 14)
		chachaQR(x, 3, 7, 11, 15)
		// 对角轮
		chachaQR(x, 0, 5, 10, 15)
		chachaQR(x, 1, 6, 11, 12)
		chachaQR(x, 2, 7, 8, 13)
		chachaQR(x, 3, 4, 9, 14)
	}
}

// chacha20Block 按 RFC 8439 第 2.3 节生成一个 64 字节块。
// key 必须 32 字节，nonce 必须 12 字节（IETF）。
func chacha20Block(key []byte, counter uint32, nonce []byte) [64]byte {
	var state [16]uint32
	copy(state[:4], chachaConstants[:])
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12] = counter
	for i := 0; i < 3; i++ {
		state[13+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	working := state
	chachaRounds(&working)
	for i := 0; i < 16; i++ {
		working[i] += state[i]
	}
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], working[i])
	}
	return out
}

// hChaCha20 用 32 字节 key 和 16 字节 nonce 派生 32 字节子密钥。
// 状态中 nonce 占据 word 12-15（无 counter），输出 word 0-3 和 12-15。
func hChaCha20(key, nonce []byte) [32]byte {
	var state [16]uint32
	copy(state[:4], chachaConstants[:])
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	for i := 0; i < 4; i++ {
		state[12+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	chachaRounds(&state)
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], state[i])
	}
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[16+i*4:], state[12+i])
	}
	return out
}

// chacha20XORKeyStream 用 counter 开始的 ChaCha20 密钥流对 src 做异或。
// dst 可以与 src 完全重叠（原地操作）。
func chacha20XORKeyStream(dst, src, key []byte, counter uint32, nonce []byte) {
	var block [64]byte
	for len(src) > 0 {
		block = chacha20Block(key, counter, nonce)
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

// leToBig 把小端字节串解释为 big.Int。
func leToBig(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(rev)
}

// bigToLE16 把 v 的低 128 位写成 16 字节小端。
func bigToLE16(v *big.Int) [16]byte {
	var out [16]byte
	be := v.Bytes()
	for i := 0; i < len(be) && i < 16; i++ {
		out[i] = be[len(be)-1-i]
	}
	return out
}

// poly1305 是 RFC 8439 第 2.5 节的 Poly1305 一次性认证器。
// 这里用标准库 math/big 实现 2^130-5 模运算，代码简洁且行为确定。
type poly1305 struct {
	r, s *big.Int
}

func newPoly1305(key []byte) *poly1305 {
	var rb, sb [16]byte
	copy(rb[:], key[:16])
	copy(sb[:], key[16:32])
	// clamp r：参见 RFC 8439 第 2.5 节。
	rb[3] &= 15
	rb[7] &= 15
	rb[11] &= 15
	rb[15] &= 15
	rb[4] &= 252
	rb[8] &= 252
	rb[12] &= 252
	return &poly1305{r: leToBig(rb[:]), s: leToBig(sb[:])}
}

// mac 计算 msg 的 16 字节 Poly1305 标签。
func (p *poly1305) mac(msg []byte) [16]byte {
	acc := new(big.Int)
	n := new(big.Int)
	var block [17]byte
	for len(msg) > 0 {
		chunk := msg
		if len(chunk) > 16 {
			chunk = chunk[:16]
		}
		block = [17]byte{}
		copy(block[:], chunk)
		block[len(chunk)] = 1
		n = leToBig(block[:])
		acc.Add(acc, n)
		acc.Mul(acc, p.r)
		acc.Mod(acc, poly1305P)
		msg = msg[len(chunk):]
	}
	acc.Add(acc, p.s)
	acc.Mod(acc, poly1305Mod128)
	return bigToLE16(acc)
}

// chacha20poly1305 实现 cipher.AEAD 接口。
// xchacha 为 true 时是 XChaCha20-Poly1305（24 字节 nonce），
// 否则是 RFC 8439 的 ChaCha20-Poly1305（12 字节 nonce）。
type chacha20poly1305 struct {
	key     [32]byte
	xchacha bool
}

var _ cipher.AEAD = (*chacha20poly1305)(nil)

func newChacha20Poly1305(key []byte, xchacha bool) (*chacha20poly1305, error) {
	if len(key) != 32 {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	c := &chacha20poly1305{xchacha: xchacha}
	copy(c.key[:], key)
	return c, nil
}

func (c *chacha20poly1305) NonceSize() int {
	if c.xchacha {
		return 24
	}
	return 12
}

func (c *chacha20poly1305) Overhead() int { return 16 }

// setupNonce 返回实际使用的密钥与 IETF 12 字节 nonce。
func (c *chacha20poly1305) setupNonce(nonce []byte) ([32]byte, [12]byte) {
	var subkey [32]byte
	var n12 [12]byte
	if c.xchacha {
		subkey = hChaCha20(c.key[:], nonce[:16])
		copy(n12[4:], nonce[16:24]) // 前 4 字节为 0
	} else {
		subkey = c.key
		copy(n12[:], nonce)
	}
	return subkey, n12
}

// pad16Len 返回把 n 字节补齐到 16 的倍数后的长度。
func pad16Len(n int) int { return (n + 15) &^ 15 }

func appendPadded(dst, src []byte) []byte {
	dst = append(dst, src...)
	if pad := (16 - len(src)%16) % 16; pad > 0 {
		dst = append(dst, make([]byte, pad)...)
	}
	return dst
}

// polyMAC 构造 RFC 8439 第 2.8 节的 MAC 数据并计算标签。
func polyMAC(p *poly1305, ciphertext, aad []byte) [16]byte {
	buf := make([]byte, 0, pad16Len(len(aad))+pad16Len(len(ciphertext))+16)
	buf = appendPadded(buf, aad)
	buf = appendPadded(buf, ciphertext)
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ciphertext)))
	buf = append(buf, lens[:]...)
	return p.mac(buf)
}

// sliceForAppend 是 crypto/cipher 包内 sliceForAppend 的等价实现。
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}

func (c *chacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.NonceSize() {
		panic("chacha20poly1305: incorrect nonce length")
	}
	subkey, n12 := c.setupNonce(nonce)
	polyKeyBlock := chacha20Block(subkey[:], 0, n12[:]) // counter=0 生成一次性 Poly1305 key
	p := newPoly1305(polyKeyBlock[:32])

	ret, out := sliceForAppend(dst, len(plaintext)+16)
	chacha20XORKeyStream(out, plaintext, subkey[:], 1, n12[:]) // counter 从 1 开始
	tag := polyMAC(p, out[:len(plaintext)], additionalData)
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (c *chacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.NonceSize() {
		panic("chacha20poly1305: incorrect nonce length")
	}
	if len(ciphertext) < 16 {
		for i := range dst {
			dst[i] = 0
		}
		return nil, errChachaOpen
	}
	subkey, n12 := c.setupNonce(nonce)
	polyKeyBlock := chacha20Block(subkey[:], 0, n12[:])
	p := newPoly1305(polyKeyBlock[:32])

	ct := ciphertext[:len(ciphertext)-16]
	tag := ciphertext[len(ciphertext)-16:]
	expected := polyMAC(p, ct, additionalData)
	if subtle.ConstantTimeCompare(tag, expected[:]) != 1 {
		for i := range dst {
			dst[i] = 0
		}
		return nil, errChachaOpen
	}
	ret, out := sliceForAppend(dst, len(ct))
	chacha20XORKeyStream(out, ct, subkey[:], 1, n12[:])
	return ret, nil
}
