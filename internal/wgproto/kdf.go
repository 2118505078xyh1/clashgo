package wgproto

import (
	"crypto/hmac"
)

// hmacBlake2s 是 HMAC-BLAKE2s-256(key, input)，输出 32 字节。
func hmacBlake2s(key, input []byte) [blake2sSize]byte {
	mac := hmac.New(newBLAKE2s256, key)
	_, _ = mac.Write(input)
	var out [blake2sSize]byte
	mac.Sum(out[:0])
	return out
}

// kdf 实现白皮书定义的 KDFn(key, input)：
//
//	tau0 = HMAC(key, input)
//	tau1 = HMAC(tau0, 0x01)
//	taui = HMAC(tau0, tau(i-1) || byte(i))
//
// out 长度必须是 32 的整数倍（32/64/96），返回前 len(out)/32 个 tau。
func kdf(out []byte, key, input []byte) {
	prk := hmacBlake2s(key, input)
	var t [blake2sSize]byte
	for i := 1; i*blake2sSize <= len(out); i++ {
		mac := hmac.New(newBLAKE2s256, prk[:])
		_, _ = mac.Write(t[:])
		_, _ = mac.Write([]byte{byte(i)})
		mac.Sum(t[:0])
		copy(out[(i-1)*blake2sSize:i*blake2sSize], t[:])
	}
}

func kdf1(out *[blake2sSize]byte, key, input []byte) {
	kdf(out[:], key, input)
}

func kdf2(out1, out2 *[blake2sSize]byte, key, input []byte) {
	var out [2 * blake2sSize]byte
	kdf(out[:], key, input)
	copy(out1[:], out[:blake2sSize])
	copy(out2[:], out[blake2sSize:])
}

func kdf3(out1, out2, out3 *[blake2sSize]byte, key, input []byte) {
	var out [3 * blake2sSize]byte
	kdf(out[:], key, input)
	copy(out1[:], out[:blake2sSize])
	copy(out2[:], out[blake2sSize:2*blake2sSize])
	copy(out3[:], out[2*blake2sSize:])
}

// mixHash 执行 h = BLAKE2s-256(h || data...)。
func mixHash(h *[blake2sSize]byte, data ...[]byte) {
	d, _ := newBLAKE2s(nil, blake2sSize)
	_, _ = d.Write(h[:])
	for _, b := range data {
		_, _ = d.Write(b)
	}
	d.Sum(h[:0])
}

// mixKey 执行 chainKey = KDF1(chainKey, data)。
func mixKey(chainKey *[blake2sSize]byte, data []byte) {
	kdf1(chainKey, chainKey[:], data)
}
