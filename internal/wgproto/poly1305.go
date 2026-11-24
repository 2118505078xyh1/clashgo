package wgproto

import "math/big"

// Poly1305 (RFC 8439 §2.5)。这里用 math/big 实现，优先保证正确性与可读性；
// 非恒定时间实现，作为简化点记录在包文档中。
var (
	poly1305P       = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	poly1305Mask128 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
)

// leBytesToBig 把小端字节串转成大整数。
func leBytesToBig(b []byte) *big.Int {
	rev := make([]byte, len(b))
	for i := range b {
		rev[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(rev)
}

// bigToLE128 把大整数的低 128 位写成 16 字节小端表示。
func bigToLE128(x *big.Int) [16]byte {
	var v big.Int
	v.And(x, poly1305Mask128)
	var out [16]byte
	be := v.Bytes()
	for i := range be {
		out[len(be)-1-i] = be[i]
	}
	return out
}

// poly1305Tag 计算 one-time authenticator 的 16 字节标签。
func poly1305Tag(key *[32]byte, msg []byte) [16]byte {
	// r = clamp(key[0:16])，按小端解析
	var rBytes [16]byte
	copy(rBytes[:], key[:16])
	rBytes[3] &= 15
	rBytes[4] &= 252
	rBytes[7] &= 15
	rBytes[8] &= 252
	rBytes[11] &= 15
	rBytes[12] &= 252
	rBytes[15] &= 15
	r := leBytesToBig(rBytes[:])
	s := leBytesToBig(key[16:32])

	acc := new(big.Int)
	var blockValue *big.Int
	padBit := new(big.Int)
	for len(msg) > 0 {
		n := len(msg)
		if n > 16 {
			n = 16
		}
		var le [16]byte
		copy(le[:], msg[:n])
		blockValue = leBytesToBig(le[:])
		// 追加 0x01 字节：整数加 2^(8*n)
		padBit.SetInt64(1)
		padBit.Lsh(padBit, uint(8*n))
		blockValue.Add(blockValue, padBit)
		acc.Add(acc, blockValue)
		acc.Mul(acc, r)
		acc.Mod(acc, poly1305P)
		msg = msg[n:]
	}
	acc.Add(acc, s)
	return bigToLE128(acc)
}
