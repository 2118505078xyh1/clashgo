package quicproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// QUIC v1 的 Initial salt（RFC 9001 Appendix A）。
var quicSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExpandLabel 是 QUIC 专用的 HKDF-Expand-Label（RFC 9001 第 5.1 节）。
// Label 前缀 "tls13 "，结构: 2字节长度 + (6+len(label)) + label + 1字节 context长度 + context。
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	// HkdfLabel = { uint16 length; label<7..255>; context<0..255> }（TLS 1.3 §7.1）
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length)) // uint16 length（输出密钥长度）
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(secret, info, length)
}

// hkdfExpand 是纯标准库 HKDF-Expand（RFC 5869）。
func hkdfExpand(secret, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		mac := hmac.New(sha256.New, secret)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// initialKeys 是从 DCID 派生的 QUIC Initial 级别密钥（client/server 双向）。
type initialKeys struct {
	clientKey, clientIV, clientHP []byte
	serverKey, serverIV, serverHP []byte
}

func deriveInitialKeys(dcid []byte) *initialKeys {
	// initialSecret = HKDF-Extract(salt, DCID)
	mac := hmac.New(sha256.New, quicSaltV1)
	mac.Write(dcid)
	initialSecret := mac.Sum(nil)

	clientSecret := hkdfExpandLabel(initialSecret, "client in", nil, sha256.Size)
	serverSecret := hkdfExpandLabel(initialSecret, "server in", nil, sha256.Size)

	k := &initialKeys{
		clientKey: hkdfExpandLabel(clientSecret, "quic key", nil, 16),
		clientIV:  hkdfExpandLabel(clientSecret, "quic iv", nil, 12),
		clientHP:  hkdfExpandLabel(clientSecret, "quic hp", nil, 16),
		serverKey: hkdfExpandLabel(serverSecret, "quic key", nil, 16),
		serverIV:  hkdfExpandLabel(serverSecret, "quic iv", nil, 12),
		serverHP:  hkdfExpandLabel(serverSecret, "quic hp", nil, 16),
	}
	return k
}

func newAEAD(key, iv []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// varint 编码 QUIC 可变长度整数（RFC 9000 第 1.1 节）。
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// nonce 由 IV 和包号异或生成（低 8 字节）。
func makeNonce(iv []byte, pn uint64) []byte {
	nonce := append([]byte(nil), iv...)
	var pnb [8]byte
	binary.BigEndian.PutUint64(pnb[:], pn)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= pnb[i]
	}
	return nonce
}
