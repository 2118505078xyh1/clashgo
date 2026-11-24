package ssrproto

// 本文件包含 SSR 传统流加密所需的密钥派生与 cipher 原语，全部为纯标准库实现。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"math/bits"
	"strings"
)

// evpBytesToKey 是 SS/SSR 传统的 OpenSSL EVP_BytesToKey(MD5) 密钥派生。
func evpBytesToKey(password []byte, size int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < size {
		h.Write(prev)
		h.Write(password)
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:size]
}

// methodSpec 描述一种流加密方法的密钥/IV 长度。
type methodSpec struct {
	keyLen int
	ivLen  int
}

// lookupMethod 规范化方法名并返回其参数。
func lookupMethod(name string) (methodSpec, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "aes-256-cfb":
		return methodSpec{32, 32}, nil
	case "aes-192-cfb":
		return methodSpec{24, 24}, nil
	case "aes-128-cfb":
		return methodSpec{16, 16}, nil
	case "chacha20":
		return methodSpec{32, 8}, nil
	default:
		return methodSpec{}, &UnsupportedMethodError{Name: name}
	}
}

// UnsupportedMethodError 表示不支持的加密方法。
type UnsupportedMethodError struct{ Name string }

func (e *UnsupportedMethodError) Error() string { return "ssrproto: unsupported method: " + e.Name }

// streamCipher 是 SSR 流加密对外暴露的最小接口（与 cipher.Stream 相同）。
type streamCipher interface {
	XORKeyStream(dst, src []byte)
}

// newStreamCipher 创建指定方向的流密码。decrypt 为 true 时是读方向。
func newStreamCipher(method string, key, iv []byte, decrypt bool) (streamCipher, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "aes-256-cfb", "aes-192-cfb", "aes-128-cfb":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return newCFBStream(block, iv, decrypt), nil
	case "chacha20":
		return newSSChachaStream(key, iv), nil
	default:
		return nil, &UnsupportedMethodError{Name: method}
	}
}

// ---------------------------------------------------------------------------
// 手写 CFB-128（segment size = block size）
// 不依赖 crypto/cipher.NewCFBEncrypter：这里自己维护反馈寄存器与密钥流块，
// 并允许 XORKeyStream 被任意长度的分块多次调用（流式语义正确）。
// ---------------------------------------------------------------------------

type cfbStream struct {
	block   cipher.Block
	reg     []byte // 反馈寄存器，长度 = block size
	ks      []byte // 当前密钥流块
	pos     int    // 当前密钥流块已消费的字节数
	decrypt bool
}

func newCFBStream(block cipher.Block, iv []byte, decrypt bool) *cfbStream {
	bs := block.BlockSize()
	if len(iv) < bs {
		// 调用方保证 iv 长度足够；防御性补齐，避免 panic。
		padded := make([]byte, bs)
		copy(padded, iv)
		iv = padded
	}
	return &cfbStream{
		block:   block,
		reg:     append([]byte(nil), iv[:bs]...),
		ks:      make([]byte, bs),
		pos:     bs, // 设为满，触发第一次调用时生成密钥流
		decrypt: decrypt,
	}
}

func (c *cfbStream) XORKeyStream(dst, src []byte) {
	bs := c.block.BlockSize()
	for i, s := range src {
		if c.pos == bs {
			c.block.Encrypt(c.ks, c.reg)
			c.pos = 0
		}
		v := s ^ c.ks[c.pos]
		dst[i] = v
		// 反馈字节：加密时为密文（=v），解密时也为密文（=原始 src）。
		feedback := v
		if c.decrypt {
			feedback = s
		}
		copy(c.reg, c.reg[1:])
		c.reg[bs-1] = feedback
		c.pos++
	}
}

// ---------------------------------------------------------------------------
// SS "chacha20" 流加密（DJB 原始变体：64 位 counter + 8 字节 nonce）
// 注意与 IETF ChaCha20（12 字节 nonce / 32 位 counter）不同。
// ---------------------------------------------------------------------------

var ssChaChaConst = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574} // "expand 32-byte k"

func ssChaChaQR(x *[16]uint32, a, b, cc, d int) {
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = bits.RotateLeft32(x[d], 16)
	x[cc] += x[d]
	x[b] ^= x[cc]
	x[b] = bits.RotateLeft32(x[b], 12)
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = bits.RotateLeft32(x[d], 8)
	x[cc] += x[d]
	x[b] ^= x[cc]
	x[b] = bits.RotateLeft32(x[b], 7)
}

func ssChaChaRounds(x *[16]uint32) {
	for i := 0; i < 10; i++ {
		ssChaChaQR(x, 0, 4, 8, 12)
		ssChaChaQR(x, 1, 5, 9, 13)
		ssChaChaQR(x, 2, 6, 10, 14)
		ssChaChaQR(x, 3, 7, 11, 15)
		ssChaChaQR(x, 0, 5, 10, 15)
		ssChaChaQR(x, 1, 6, 11, 12)
		ssChaChaQR(x, 2, 7, 8, 13)
		ssChaChaQR(x, 3, 4, 9, 14)
	}
}

func ssChaCha20Block(key *[32]byte, counter uint64, nonce [8]byte) [64]byte {
	var state [16]uint32
	copy(state[:4], ssChaChaConst[:])
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12] = uint32(counter)
	state[13] = uint32(counter >> 32)
	state[14] = binary.LittleEndian.Uint32(nonce[0:4])
	state[15] = binary.LittleEndian.Uint32(nonce[4:8])
	working := state
	ssChaChaRounds(&working)
	for i := range working {
		working[i] += state[i]
	}
	var out [64]byte
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], working[i])
	}
	return out
}

type ssChachaStream struct {
	key     [32]byte
	nonce   [8]byte
	counter uint64
	ks      [64]byte
	pos     int
}

func newSSChachaStream(key, nonce []byte) *ssChachaStream {
	s := &ssChachaStream{pos: 64}
	copy(s.key[:], key)
	copy(s.nonce[:], nonce)
	return s
}

func (s *ssChachaStream) XORKeyStream(dst, src []byte) {
	for i, v := range src {
		if s.pos == 64 {
			s.ks = ssChaCha20Block(&s.key, s.counter, s.nonce)
			s.counter++
			s.pos = 0
		}
		dst[i] = v ^ s.ks[s.pos]
		s.pos++
	}
}

// ---------------------------------------------------------------------------
// 校验和与随机数小工具
// ---------------------------------------------------------------------------

// calcCRC32 等价于 shadowsocksr 的 CalcCRC32：标准 CRC32-IEEE，返回 crc^0xffffffff。
func calcCRC32(data []byte, end int) uint32 {
	if end > len(data) {
		end = len(data)
	}
	return crc32.ChecksumIEEE(data[:end])
}

// randBytes 用 crypto/rand 填充 n 字节。
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// randInt 返回 [0, n) 范围内的随机整数（crypto/rand）。
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return int(binary.LittleEndian.Uint64(b[:]) % uint64(n))
}
