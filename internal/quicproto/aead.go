package quicproto

// This file implements the QUIC v1 packet protection (RFC 9001 §5):
// AEAD encryption with nonces built from IV XOR packet number, and header
// protection using AES-ECB.  All keys are derived from TLS 1.3 traffic
// secrets via HKDF-Expand-Label with the label prefixes from RFC 9001 §5.1.
//
// AES-GCM (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384) and the locally
// implemented ChaCha20-Poly1305 (TLS_CHACHA20_POLY1305_SHA256, RFC 8439) are
// supported, including their respective header-protection algorithms.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// packetProtection holds the keys for a single encryption level / direction.
type packetProtection struct {
	aead     cipher.AEAD  // packet payload AEAD (AES-GCM or ChaCha20-Poly1305)
	hp       cipher.Block // AES header protection block cipher (AES-ECB); nil for ChaCha
	hpChaCha bool         // use RFC 9001 §5.4.4 ChaCha20 header protection
	hpKey    []byte       // 32-byte ChaCha20 header-protection key
	iv       []byte       // 12-byte nonce prefix
	keyLen   int          // AEAD key length in bytes (16 or 32)

	// The traffic secret, hash and suite are retained so that a QUIC key
	// update (RFC 9001 §6) can derive the next key generation on demand.
	secret []byte
	h      func() hash.Hash
	suite  uint16
}

// hkdfExpandHash is RFC 5869 HKDF-Expand parameterised by hash function.
func hkdfExpandHash(h func() hash.Hash, secret, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		mac := hmac.New(h, secret)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// expandLabelWithHash is QUIC's HKDF-Expand-Label using the hash associated
// with the given TLS 1.3 cipher suite (RFC 9001 §5.1).
func expandLabelWithHash(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpandHash(h, secret, info, length)
}

// newPacketProtection derives key/IV/HP from a TLS traffic secret and suite.
func newPacketProtection(secret []byte, suite uint16) (*packetProtection, error) {
	var h func() hash.Hash
	var keyLen int
	var hpChaCha bool
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		h, keyLen = sha256.New, 16
	case tls.TLS_AES_256_GCM_SHA384:
		h, keyLen = sha512.New384, 32
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		h, keyLen, hpChaCha = sha256.New, 32, true
	default:
		return nil, fmt.Errorf("quicproto: unsupported QUIC cipher suite 0x%04x", suite)
	}
	key := expandLabelWithHash(h, secret, "quic key", nil, keyLen)
	iv := expandLabelWithHash(h, secret, "quic iv", nil, 12)
	hpKey := expandLabelWithHash(h, secret, "quic hp", nil, keyLen)

	p := &packetProtection{
		iv:       iv,
		keyLen:   keyLen,
		hpChaCha: hpChaCha,
		secret:   append([]byte(nil), secret...),
		h:        h,
		suite:    suite,
	}
	if hpChaCha {
		// RFC 9001 §5.4.4: ChaCha20 header protection uses a 32-byte HP key.
		p.hpKey = hpKey
		aead, err := newChaCha20Poly1305(key)
		if err != nil {
			return nil, err
		}
		p.aead = aead
		return p, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	p.aead = aead
	p.hp = hpBlock
	return p, nil
}

// update derives the next packet protection generation (RFC 9001 §6.1):
//
//	secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length)
//
// Per RFC 9001 §6.1 the header protection key is NOT changed by a key update;
// only the key and IV are regenerated.  Keeping the HP key stable lets a
// receiver read the Key Phase bit before deciding which keys to use.
func (p *packetProtection) update() (*packetProtection, error) {
	if len(p.secret) == 0 || p.h == nil {
		return nil, errors.New("quicproto: key update requires the traffic secret")
	}
	nextSecret := expandLabelWithHash(p.h, p.secret, "quic ku", nil, len(p.secret))
	next, err := newPacketProtection(nextSecret, p.suite)
	if err != nil {
		return nil, err
	}
	// Header protection keys are not updated (RFC 9001 §6.1).
	next.hpChaCha = p.hpChaCha
	next.hpKey = append([]byte(nil), p.hpKey...)
	next.hp = p.hp
	return next, nil
}

// newPacketProtectionFromRaw builds protection from already-derived
// key/IV/HP bytes (used for the Initial level).
func newPacketProtectionFromRaw(key, iv, hp []byte) (*packetProtection, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	return &packetProtection{aead: aead, hp: hpBlock, iv: append([]byte(nil), iv...), keyLen: len(key)}, nil
}

// nonce returns IV with the low 8 bytes XORed with the packet number.
func (p *packetProtection) nonce(pn uint64) []byte {
	nonce := append([]byte(nil), p.iv...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], pn)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-8+i] ^= b[i]
	}
	return nonce
}

// hpMask computes the 5-byte header protection mask from a ciphertext sample.
func (p *packetProtection) hpMask(pkt []byte, pnOffset int) ([5]byte, error) {
	var mask [5]byte
	sampleOffset := pnOffset + 4
	need := 16 // AES needs a 16-byte ECB block; ChaCha20 also samples 16 bytes
	if sampleOffset+need > len(pkt) {
		return mask, errors.New("quicproto: packet too short for header protection sample")
	}
	sample := pkt[sampleOffset : sampleOffset+16]
	if p.hpChaCha {
		return chacha20HPMask(p.hpKey, sample)
	}
	var sampleBuf, blockOut [16]byte
	copy(sampleBuf[:], sample)
	p.hp.Encrypt(blockOut[:], sampleBuf[:])
	copy(mask[:], blockOut[:5])
	return mask, nil
}

// seal encrypts payload and applies header protection.
//
// header is the full cleartext header, including the packet number field with
// the real packet number already written.  pnOffset is the index at which the
// packet number field starts and pnLen its length (1..4).
func (p *packetProtection) seal(header []byte, pnOffset, pnLen int, payload []byte, pn uint64) ([]byte, error) {
	aad := append([]byte(nil), header...)
	ciphertext := p.aead.Seal(nil, p.nonce(pn), payload, aad)
	pkt := append(aad, ciphertext...)

	mask, err := p.hpMask(pkt, pnOffset)
	if err != nil {
		return nil, err
	}
	hpBits := byte(0x0f) // long header: low 4 bits
	if pkt[0]&0x80 == 0 {
		hpBits = 0x1f // short header: low 5 bits
	}
	pkt[0] ^= mask[0] & hpBits
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt, nil
}

// openFull removes header protection and decrypts one packet.  The AEAD nonce
// MUST be built from the FULL packet number (RFC 9000 Appendix A.3), so the
// truncated PN recovered from the header is decoded against `largest` first.
// It returns the full PN, its encoded length, the cleartext header and payload.
func (p *packetProtection) openFull(data []byte, pnOffset int, isLong bool, largest uint64) (fullPN uint64, pnLen int, header, payload []byte, err error) {
	mask, err := p.hpMask(data, pnOffset)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	hpBits := byte(0x0f)
	if !isLong {
		hpBits = 0x1f
	}
	first := data[0] ^ (mask[0] & hpBits)
	pnLen = int(first&0x03) + 1
	if pnOffset+pnLen > len(data) {
		return 0, 0, nil, nil, errors.New("quicproto: truncated packet number")
	}
	pnBytes := make([]byte, pnLen)
	copy(pnBytes, data[pnOffset:pnOffset+pnLen])
	for i := 0; i < pnLen; i++ {
		pnBytes[i] ^= mask[1+i]
	}
	truncated := uint64(0)
	for _, b := range pnBytes {
		truncated = truncated<<8 | uint64(b)
	}
	fullPN = decodePacketNumber(largest, truncated, pnLen)

	header = append([]byte(nil), data[:pnOffset+pnLen]...)
	header[0] = first
	copy(header[pnOffset:], pnBytes)

	ciphertext := data[pnOffset+pnLen:]
	plaintext, err := p.aead.Open(nil, p.nonce(fullPN), ciphertext, header)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	return fullPN, pnLen, header, plaintext, nil
}

// open is the legacy convenience wrapper for packets whose full PN is known
// to equal the truncated value in the header (4-byte PNs, or the test vectors).
func (p *packetProtection) open(data []byte, pnOffset int, isLong bool) (pn uint64, header, payload []byte, err error) {
	fullPN, _, header, payload, err := p.openFull(data, pnOffset, isLong, 0)
	return fullPN, header, payload, err
}

// decodePacketNumber implements RFC 9000 Appendix A.3.
func decodePacketNumber(largest, truncated uint64, pnLen int) uint64 {
	pnWin := uint64(1) << (uint(pnLen) * 8)
	pnHalf := pnWin / 2
	pnMask := pnWin - 1
	expected := largest + 1
	candidate := (expected & ^pnMask) | truncated
	if candidate+pnHalf < expected {
		candidate += pnWin
	}
	return candidate
}
