// Package wgproto - BLAKE2s (RFC 7693) 的纯标准库实现。
//
// Go 标准库没有 blake2s，而 Noise_IKpsk2 的 HASH/MAC/KDF 都建立在它之上，
// 因此这里实现 BLAKE2s-256（普通哈希与 HMAC 底层）以及 BLAKE2s-128（带密钥 MAC）。
//
// 该文件只依赖 encoding/binary / hash / math/bits，不含任何外部依赖。
package wgproto

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

const (
	blake2sBlockSize = 64
	blake2sSize      = 32
	blake2sSize128   = 16
)

var blake2sIV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// sigma 是 RFC 7693 定义的 10 轮消息字置换。
var blake2sSigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

var errBlake2sKeySize = errors.New("blake2s: key must be at most 32 bytes")

// blake2sDigest 实现 hash.Hash，同时支持带密钥模式（keyed BLAKE2s）。
// c[0],c[1] 与 x/crypto/blake2s 一致：压缩前是"已压缩字节数 - (64-offset)"，
// hashBlocks 每块加 64，最终恰好得到 t = 已处理字节总数（含 key block）。
type blake2sDigest struct {
	h      [8]uint32
	c      [2]uint32
	size   int
	block  [blake2sBlockSize]byte
	offset int
	key    [blake2sBlockSize]byte
	keyLen int
}

func newBLAKE2s256() hash.Hash {
	d, _ := newBLAKE2s(nil, blake2sSize)
	return d
}

// newBLAKE2s 创建一个 BLAKE2s 哈希；key 非空时为 keyed MAC 模式。
func newBLAKE2s(key []byte, size int) (hash.Hash, error) {
	if len(key) > blake2sSize {
		return nil, errBlake2sKeySize
	}
	d := &blake2sDigest{size: size, keyLen: len(key)}
	copy(d.key[:], key)
	d.Reset()
	return d, nil
}

// blake2sSum256 计算 BLAKE2s-256(data)。
func blake2sSum256(data []byte) [blake2sSize]byte {
	d, _ := newBLAKE2s(nil, blake2sSize)
	_, _ = d.Write(data)
	var out [blake2sSize]byte
	d.(*blake2sDigest).finalize(&out)
	return out
}

// blake2sMAC 计算 Keyed-BLAKE2s(key, data)，输出 size 字节（WireGuard 用 16）。
func blake2sMAC(key, data []byte, size int) []byte {
	h, err := newBLAKE2s(key, size)
	if err != nil {
		panic(err)
	}
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func (d *blake2sDigest) Size() int      { return d.size }
func (d *blake2sDigest) BlockSize() int { return blake2sBlockSize }

func (d *blake2sDigest) Reset() {
	d.h = blake2sIV
	// h[0] = IV[0] XOR (0x01010000 | (keylen << 8) | digestlen)
	d.h[0] ^= uint32(d.size) | uint32(d.keyLen)<<8 | (1 << 16) | (1 << 24)
	d.offset, d.c[0], d.c[1] = 0, 0, 0
	if d.keyLen > 0 {
		d.block = d.key
		d.offset = blake2sBlockSize
	}
}

func (d *blake2sDigest) Write(p []byte) (n int, err error) {
	n = len(p)
	if d.offset > 0 {
		remaining := blake2sBlockSize - d.offset
		if n <= remaining {
			d.offset += copy(d.block[d.offset:], p)
			return n, nil
		}
		copy(d.block[d.offset:], p[:remaining])
		blake2sHashBlocks(&d.h, &d.c, 0, d.block[:])
		d.offset = 0
		p = p[remaining:]
	}
	if length := len(p); length > blake2sBlockSize {
		nn := length &^ (blake2sBlockSize - 1)
		if length == nn {
			nn -= blake2sBlockSize
		}
		blake2sHashBlocks(&d.h, &d.c, 0, p[:nn])
		p = p[nn:]
	}
	d.offset += copy(d.block[:], p)
	return n, nil
}

func (d *blake2sDigest) Sum(in []byte) []byte {
	var out [blake2sSize]byte
	d.finalize(&out)
	return append(in, out[:d.size]...)
}

func (d *blake2sDigest) finalize(out *[blake2sSize]byte) {
	var block [blake2sBlockSize]byte
	h := d.h
	c := d.c
	copy(block[:], d.block[:d.offset])
	remaining := uint32(blake2sBlockSize - d.offset)
	if c[0] < remaining {
		c[1]--
	}
	c[0] -= remaining
	blake2sHashBlocks(&h, &c, 0xffffffff, block[:])
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
}

func blake2sHashBlocks(h *[8]uint32, c *[2]uint32, flag uint32, blocks []byte) {
	var m [16]uint32
	var v [16]uint32
	c0, c1 := c[0], c[1]

	for i := 0; i < len(blocks); {
		c0 += blake2sBlockSize
		if c0 < blake2sBlockSize {
			c1++
		}

		for j := 0; j < 8; j++ {
			v[j] = h[j]
			v[j+8] = blake2sIV[j]
		}
		v[12] ^= c0
		v[13] ^= c1
		v[14] ^= flag

		for j := range m {
			m[j] = binary.LittleEndian.Uint32(blocks[i:])
			i += 4
		}

		for r := range blake2sSigma {
			s := &blake2sSigma[r]
			blake2sG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
			blake2sG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
			blake2sG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
			blake2sG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
			blake2sG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
			blake2sG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
			blake2sG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
			blake2sG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
		}

		for j := 0; j < 8; j++ {
			h[j] ^= v[j] ^ v[j+8]
		}
	}
	c[0], c[1] = c0, c1
}

func blake2sG(v *[16]uint32, a, b, cc, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	v[cc] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[cc], -12)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	v[cc] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[cc], -7)
}
