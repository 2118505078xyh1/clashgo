package vproto

// VMess legacy (alterId > 0 / "aes-128-cfb") support.
//
// The legacy protocol differs from AEAD in two independent ways:
//
//  1. The request header is not wrapped in AEAD envelopes. Instead it is
//     prefixed by a 16-byte HMAC-MD5 tag derived from the current timestamp
//     and encrypted with AES-128-CFB using a key derived from the timestamp.
//  2. The payload stream uses AES-128-CFB (full 128-bit feedback) and each
//     write is framed as [2-byte length][4-byte FNV1a checksum][payload],
//     all of which is covered by the same CFB stream.
//
// Only the Go standard library is used. In particular CFB-128 is implemented
// here rather than relying on any third-party stream cipher.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
)

// cfb128 implements the cipher feedback mode with a full-block (128-bit)
// feedback register, i.e. CFB-128. It satisfies cipher.Stream.
//
// Encryption and decryption differ only in what is fed back into the
// register: for encryption it is the produced ciphertext, for decryption it
// is the ciphertext that was read.
type cfb128 struct {
	block   cipher.Block
	iv      [aes.BlockSize]byte
	out     [aes.BlockSize]byte
	pos     int
	decrypt bool
}

var _ cipher.Stream = (*cfb128)(nil)

func newCFB128(block cipher.Block, iv []byte, decrypt bool) *cfb128 {
	// pos = blockSize forces the first keystream block to be generated before
	// any bytes are XORed (this mirrors crypto/cipher's outUsed initialiser).
	c := &cfb128{block: block, pos: aes.BlockSize, decrypt: decrypt}
	copy(c.iv[:], iv)
	return c
}

// newCFBEncrypter128 returns a CFB-128 stream encryptor.
func newCFBEncrypter128(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newCFB128(block, iv, false), nil
}

// newCFBDecrypter128 returns a CFB-128 stream decryptor.
func newCFBDecrypter128(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return newCFB128(block, iv, true), nil
}

func (c *cfb128) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if c.pos == aes.BlockSize {
			c.block.Encrypt(c.out[:], c.iv[:])
			c.pos = 0
		}
		n := aes.BlockSize - c.pos
		if n > len(src) {
			n = len(src)
		}
		for i := 0; i < n; i++ {
			b := src[i]
			out := b ^ c.out[c.pos+i]
			dst[i] = out
			if c.decrypt {
				c.iv[c.pos+i] = b // feedback is the incoming ciphertext
			} else {
				c.iv[c.pos+i] = out // feedback is the produced ciphertext
			}
		}
		c.pos += n
		dst, src = dst[n:], src[n:]
	}
}

// cfbReader wraps an io.Reader with a cipher.Stream so that every byte read
// is decrypted in place. The stream state is carried across Read calls, which
// is essential for VMess where the response header and the data frames share
// the same CFB stream.
type cfbReader struct {
	upstream io.Reader
	stream   cipher.Stream
}

func newCFBReader(upstream io.Reader, key, iv []byte) (*cfbReader, error) {
	s, err := newCFBDecrypter128(key, iv)
	if err != nil {
		return nil, err
	}
	return &cfbReader{upstream: upstream, stream: s}, nil
}

func (r *cfbReader) Read(p []byte) (int, error) {
	n, err := r.upstream.Read(p)
	if n > 0 {
		r.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// vmessAlterKey derives the alterId key from the user UUID as specified by
// VMess: MD5(uuid || "16167dc8-16b6-4e6d-b8bb-65dd68113a81"), with an extra
// salt appended in the astronomically unlikely event of a collision.
func vmessAlterKey(uuid [16]byte) [16]byte {
	h := md5.New()
	_, _ = h.Write(uuid[:])
	_, _ = h.Write([]byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
	var out [16]byte
	for {
		h.Sum(out[:0])
		if out != uuid {
			return out
		}
		_, _ = h.Write([]byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
	}
}

// vmessLegacyIDHash returns the 16-byte HMAC-MD5 authentication tag that
// prefixes a legacy request. The message is the big-endian Unix timestamp.
func vmessLegacyIDHash(alterKey [16]byte, timestamp int64) [16]byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	h := hmac.New(md5.New, alterKey[:])
	_, _ = h.Write(ts[:])
	var out [16]byte
	h.Sum(out[:0])
	return out
}

// vmessLegacyTimeIV derives the AES-CFB IV used to encrypt a legacy header
// from four big-endian copies of the timestamp.
func vmessLegacyTimeIV(timestamp int64) [16]byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))
	h := md5.New()
	for i := 0; i < 4; i++ {
		_, _ = h.Write(ts[:])
	}
	var out [16]byte
	h.Sum(out[:0])
	return out
}

// vmessResponseLegacyKeys returns the MD5-derived response key and IV used by
// the legacy protocol. (The AEAD protocol uses SHA-256 for this purpose.)
func vmessResponseLegacyKeys(requestKey, requestNonce [16]byte) (key, iv [16]byte) {
	key = md5.Sum(requestKey[:])
	iv = md5.Sum(requestNonce[:])
	return
}

// writeLegacyFrame encrypts and writes one legacy payload frame. The caller
// must limit p to vmessWriteChunk bytes so that the 16-bit length cannot
// overflow.
func (c *vmessConn) writeLegacyFrame(p []byte) error {
	h := fnv.New32a()
	_, _ = h.Write(p)
	frame := make([]byte, 2+4+len(p))
	binary.BigEndian.PutUint16(frame[0:2], uint16(4+len(p)))
	binary.BigEndian.PutUint32(frame[2:6], h.Sum32())
	copy(frame[6:], p)
	c.writeCFB.XORKeyStream(frame, frame)
	_, err := c.Conn.Write(frame)
	return err
}

// readNextLegacyChunk reads and verifies one legacy payload frame from the
// CFB-decrypted response stream.
func (c *vmessConn) readNextLegacyChunk() error {
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.readStream, lenBuf[:]); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(lenBuf[:]))
	if length < 4 {
		return fmt.Errorf("%w: %d", ErrBadChunkLength, length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(c.readStream, data); err != nil {
		return err
	}
	h := fnv.New32a()
	_, _ = h.Write(data[4:])
	if h.Sum32() != binary.BigEndian.Uint32(data[:4]) {
		return fmt.Errorf("vproto: bad VMess chunk checksum")
	}
	c.readBuf = data[4:]
	c.readOff = 0
	return nil
}
