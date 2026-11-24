// Package ssproto 是纯标准库实现的 Shadowsocks AEAD 协议客户端。
// 支持 aes-128-gcm / aes-192-gcm / aes-256-gcm、
// chacha20-ietf-poly1305 / xchacha20-ietf-poly1305（SIP022 AEAD 流与 UDP）。
package ssproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"net"
	"strings"
	"sync"
)

const maxPacketSize = 0x3FFF // 16383，SS AEAD 单包上限

// Method 描述一个 SS 加密方法。
type Method struct {
	name    string
	keyLen  int
	key     []byte // 主密钥（由密码派生）
	newAEAD func(key []byte) (cipher.AEAD, error)
}

// NewMethod 根据方法名和密码创建加密方法。
func NewMethod(name, password string) (*Method, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var keyLen int
	var newAEAD func(key []byte) (cipher.AEAD, error)
	switch name {
	case "aes-128-gcm":
		keyLen, newAEAD = 16, newAESGCM
	case "aes-192-gcm":
		keyLen, newAEAD = 24, newAESGCM
	case "aes-256-gcm":
		keyLen, newAEAD = 32, newAESGCM
	case "chacha20-ietf-poly1305":
		keyLen, newAEAD = 32, newChaCha20IETFPoly1305
	case "xchacha20-ietf-poly1305":
		keyLen, newAEAD = 32, newXChaCha20IETFPoly1305
	default:
		return nil, &UnsupportedError{Name: name}
	}
	return &Method{
		name: name, keyLen: keyLen,
		key: evpBytesToKey([]byte(password), keyLen), newAEAD: newAEAD,
	}, nil
}

// Name 返回规范化后的方法名。
func (m *Method) Name() string { return m.name }

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newChaCha20IETFPoly1305(key []byte) (cipher.AEAD, error) {
	return newChacha20Poly1305(key, false)
}

func newXChaCha20IETFPoly1305(key []byte) (cipher.AEAD, error) {
	return newChacha20Poly1305(key, true)
}

// UnsupportedError 表示不支持的加密方法。
type UnsupportedError struct{ Name string }

func (e *UnsupportedError) Error() string { return "unsupported ss method: " + e.Name }

// evpBytesToKey 是 SS 传统的 MD5 密钥派生（OpenSSL EVP_BytesToKey 等价）。
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

// hkdfSHA1 是纯标准库实现的 HKDF-SHA1（RFC 5869），替代 x/crypto/hkdf。
func hkdfSHA1(secret, salt, info []byte, outLen int) []byte {
	// Extract: PRK = HMAC(salt, secret)，salt 为空时用全零（SHA1 长度 20）。
	if len(salt) == 0 {
		salt = make([]byte, sha1.Size)
	}
	mac := hmac.New(sha1.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	// Expand: T(i) = HMAC(PRK, T(i-1) || info || byte(i))
	out := make([]byte, 0, outLen)
	var t []byte
	for i := byte(1); len(out) < outLen; i++ {
		mac = hmac.New(sha1.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{i})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:outLen]
}

// subkey 用 salt 从主密钥派生子密钥（HKDF-SHA1, info="ss-subkey"）。
func (m *Method) subkey(salt []byte) (cipher.AEAD, error) {
	key := hkdfSHA1(m.key, salt, []byte("ss-subkey"), m.keyLen)
	return m.newAEAD(key)
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// streamConn 包装 net.Conn，自动做 SS AEAD 加解密。
type streamConn struct {
	net.Conn
	readCipher, writeCipher cipher.AEAD
	readNonce, writeNonce   []byte
	rbuf                    []byte // 已解密待读数据
	muR, muW                sync.Mutex
}

func (c *streamConn) Read(b []byte) (int, error) {
	c.muR.Lock()
	defer c.muR.Unlock()
	for len(c.rbuf) == 0 {
		if err := c.readPacket(); err != nil {
			return 0, err
		}
	}
	n := copy(b, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// readPacket 读一个加密包：先读 2+tag 字节的加密长度，再读 len+tag 字节的加密数据。
func (c *streamConn) readPacket() error {
	encLen := make([]byte, 2+c.readCipher.Overhead())
	if _, err := io.ReadFull(c.Conn, encLen); err != nil {
		return err
	}
	lenPT, err := c.readCipher.Open(nil, c.readNonce, encLen, nil)
	if err != nil {
		return err
	}
	incNonce(c.readNonce)
	n := int(lenPT[0])<<8 | int(lenPT[1])
	enc := make([]byte, n+c.readCipher.Overhead())
	if _, err := io.ReadFull(c.Conn, enc); err != nil {
		return err
	}
	pt, err := c.readCipher.Open(nil, c.readNonce, enc, nil)
	if err != nil {
		return err
	}
	incNonce(c.readNonce)
	c.rbuf = pt
	return nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	c.muW.Lock()
	defer c.muW.Unlock()
	total := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxPacketSize {
			n = maxPacketSize
		}
		data := b[:n]
		var lenBuf [2]byte
		lenBuf[0] = byte(n >> 8)
		lenBuf[1] = byte(n)
		sealedLen := c.writeCipher.Seal(nil, c.writeNonce, lenBuf[:], nil)
		incNonce(c.writeNonce)
		sealedData := c.writeCipher.Seal(nil, c.writeNonce, data, nil)
		incNonce(c.writeNonce)
		buf := make([]byte, 0, len(sealedLen)+len(sealedData))
		buf = append(buf, sealedLen...)
		buf = append(buf, sealedData...)
		if _, err := c.Conn.Write(buf); err != nil {
			return total, err
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// Dial 建立 SS 连接：TCP 连服务端 → 发 salt + 加密的目标地址 → 返回加密流。
func (m *Method) Dial(conn net.Conn, host string, port uint16) (net.Conn, error) {
	salt := make([]byte, m.keyLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	writeCipher, err := m.subkey(salt)
	if err != nil {
		return nil, err
	}
	// 写 salt。
	if _, err := conn.Write(salt); err != nil {
		return nil, err
	}
	// 加密的目标地址（SOCKS5 ATYP 格式）。
	addr := encodeAddr(host, port)
	writeNonce := make([]byte, writeCipher.NonceSize())
	var lenBuf [2]byte
	lenBuf[0] = byte(len(addr) >> 8)
	lenBuf[1] = byte(len(addr))
	packet := writeCipher.Seal(nil, writeNonce, lenBuf[:], nil)
	incNonce(writeNonce)
	packet = append(packet, writeCipher.Seal(nil, writeNonce, addr, nil)...)
	incNonce(writeNonce)
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	// 读服务端 salt，派生读密钥。
	respSalt := make([]byte, m.keyLen)
	if _, err := io.ReadFull(conn, respSalt); err != nil {
		return nil, err
	}
	readCipher, err := m.subkey(respSalt)
	if err != nil {
		return nil, err
	}
	return &streamConn{
		Conn:       conn,
		readCipher: readCipher, writeCipher: writeCipher,
		readNonce:  make([]byte, readCipher.NonceSize()),
		writeNonce: writeNonce,
	}, nil
}

// encodeAddr 把 host:port 编码成 SOCKS5 ATYP+ADDR+PORT。
func encodeAddr(host string, port uint16) []byte {
	var buf []byte
	if ip := parseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 1)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 4)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		buf = append(buf, 3, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

func parseIP(s string) net.IP { return net.ParseIP(s) }
