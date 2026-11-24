// Package reality 用标准库实现 VLESS-Reality 客户端传输层。
//
// Reality 的服务端会在 TLS 1.3 握手里返回一个自签名 Ed25519 证书，
// 客户端需要用 ECDH + HKDF 得到的 authKey 校验该证书上的 HMAC 签名。
// 这里手工构造 ClientHello 并完成 TLS 1.3 握手，避免引入 utls 依赖。
package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"

	"clashgo/internal/quicproto"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"time"
)

// Config 是 Reality 出站所需参数。
type Config struct {
	ServerName string // SNI，必须是服务端允许的伪装域名
	PublicKey  string // 服务端 X25519 公钥（base64）
	ShortID    string // 短 ID（十六进制，最多 8 字节）
	Flow       string // VLESS flow，仅保留供上层使用
}

// Dial 在已建立的 TCP 连接上完成 Reality + TLS 1.3 握手。
func Dial(ctx context.Context, raw net.Conn, cfg Config) (net.Conn, error) {
	if raw == nil {
		return nil, errors.New("reality: nil connection")
	}
	serverPub, err := decodePublicKey(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	shortID, err := decodeShortID(cfg.ShortID)
	if err != nil {
		return nil, err
	}
	if cfg.ServerName == "" {
		return nil, errors.New("reality: empty server name")
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
		defer raw.SetDeadline(time.Time{})
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var random [32]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return nil, err
	}

	// 先构造 session id 为零的 ClientHello，它同时是 auth blob 的 AAD。
	helloZero := buildClientHello(cfg.ServerName, random[:], priv.PublicKey().Bytes())
	if len(helloZero) < 39+32 {
		return nil, errors.New("reality: short client hello")
	}
	shared, err := priv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	authKey := deriveAuthKey(shared, random[:])
	sessionID, err := sealSessionID(authKey, random[:], shortID, helloZero)
	if err != nil {
		return nil, err
	}
	hello := append([]byte(nil), helloZero...)
	copy(hello[39:39+32], sessionID)

	if err := writeRecord(raw, recordHandshake, hello); err != nil {
		return nil, err
	}

	typ, payload, err := readRecord(raw)
	if err != nil {
		return nil, err
	}
	if typ != recordHandshake || len(payload) < 4 || payload[0] != hsServerHello {
		return nil, fmt.Errorf("reality: unexpected server flight (record=%d msg=%d)", typ, payload[0])
	}
	// 先从 ServerHello 取协商的 cipher suite，再按它选择 transcript hash
	// （Xray Reality 用伪装站点的套件，可能是 AES-256/SHA-384 或 ChaCha20）。
	serverShare, suiteID, err := parseServerHello(payload)
	if err != nil {
		return nil, err
	}
	suite, err := suiteFor(suiteID)
	if err != nil {
		return nil, err
	}
	transcript := newHandshakeHash(suite.hash)
	transcript.Write(hello)
	transcript.Write(payload)
	peer, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		return nil, err
	}
	tlsShared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}

	hsSecret, cHs, sHs, err := keySchedule(tlsShared, transcript.Sum(), suite)
	if err != nil {
		return nil, err
	}
	if _, err := readServerFlight(raw, sHs, transcript, authKey, suite); err != nil {
		return nil, err
	}

	// 应用数据密钥的 transcript 只到服务端 Finished（客户端 Finished 之前）。
	appTranscript := transcript.Sum()

	// 发送客户端 Finished，并派生应用数据密钥。
	clientFinishedKey := expandLabel(cHs.secret, "finished", nil, suite.hashSize, suite.hash)
	finishedBody := hmacMAC(clientFinishedKey, transcript.Sum(), suite.hash)
	clientFinished := make([]byte, 4, 4+len(finishedBody))
	clientFinished[0] = hsFinished
	clientFinished[1], clientFinished[2], clientFinished[3] = 0, 0, byte(len(finishedBody))
	clientFinished = append(clientFinished, finishedBody...)
	transcript.Write(clientFinished)
	if err := writeRecord(raw, recordAppData, cHs.encrypt(innerHandshake, clientFinished)); err != nil {
		return nil, err
	}

	cAp, sAp, err := applicationKeys(hsSecret, appTranscript, suite)
	if err != nil {
		return nil, err
	}
	return &tls13Conn{Conn: raw, in: sAp, out: cAp}, nil
}

func decodePublicKey(s string) (*ecdh.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("reality: empty public key")
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if raw, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("reality: invalid public key %q", s)
	}
	return ecdh.X25519().NewPublicKey(raw)
}

func decodeShortID(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return make([]byte, 8), nil
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("reality: invalid short id %q: %w", s, err)
	}
	if len(raw) > 8 {
		raw = raw[:8]
	}
	out := make([]byte, 8)
	copy(out, raw)
	return out, nil
}

// deriveAuthKey 与 Xray/mihomo 一致：HKDF(ikm=ECDH, salt=random[:20], info="REALITY")。
func deriveAuthKey(shared, random []byte) []byte {
	prk := hkdfExtract(sha256.New, random[:20], shared)
	return hkdfExpand(prk, []byte("REALITY"), 32, sha256.New)
}

// sealSessionID 生成 32 字节的认证 session id（16 字节明文 + 16 字节 GCM tag）。
func sealSessionID(authKey, random, shortID, aad []byte) ([]byte, error) {
	plain := make([]byte, 16)
	binary.BigEndian.PutUint64(plain[:8], uint64(time.Now().Unix()))
	copy(plain[8:16], shortID)
	plain[0], plain[1], plain[2] = 1, 8, 2
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(make([]byte, 0, 32), random[20:32], plain, aad), nil
}

// --- TLS 1.3 基础工具 -------------------------------------------------------

const (
	recordHandshake = 22
	recordAppData   = 23
	recordAlert     = 21
	recordCCS       = 20

	hsClientHello         = 1
	hsServerHello         = 2
	hsNewSessionTicket    = 4
	hsEncryptedExtensions = 8
	hsCertificate         = 11
	hsCertificateVerify   = 15
	hsFinished            = 20

	innerHandshake = 22
	innerAppData   = 23

	clientHelloSessionOffset = 39 // ClientHello 消息体内 session id 的起始位置
)

func u16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

func u24(v int) []byte { return []byte{byte(v >> 16), byte(v >> 8), byte(v)} }

func appendExt(dst []byte, tag uint16, data []byte) []byte {
	dst = append(dst, byte(tag>>8), byte(tag))
	dst = append(dst, u16(len(data))...)
	return append(dst, data...)
}

func buildClientHello(serverName string, random, pub []byte) []byte {
	var exts []byte
	// SNI
	sni := u16(len(serverName) + 3)
	sni = append(sni, 0)
	sni = append(sni, u16(len(serverName))...)
	sni = append(sni, serverName...)
	exts = appendExt(exts, 0x0000, sni)

	// supported_groups: x25519
	exts = appendExt(exts, 0x000a, append(u16(2), 0x00, 0x1d))

	// ec_point_formats
	exts = appendExt(exts, 0x000b, []byte{1, 0})

	// signature_algorithms
	sigs := []uint16{0x0403, 0x0804, 0x0805, 0x0807, 0x0808, 0x0201}
	sigData := u16(len(sigs) * 2)
	for _, s := range sigs {
		sigData = append(sigData, byte(s>>8), byte(s))
	}
	exts = appendExt(exts, 0x000d, sigData)

	// supported_versions 使用 1 字节长度前缀（ClientHello 里不是 uint16）。
	exts = appendExt(exts, 0x002b, []byte{4, 0x03, 0x04, 0x03, 0x03})

	// psk_key_exchange_modes
	exts = appendExt(exts, 0x002d, []byte{1, 1})

	// ALPN: h2, http/1.1
	alpn := u16(12)
	alpn = append(alpn, 2, 'h', '2', 8)
	alpn = append(alpn, []byte("http/1.1")...)
	exts = appendExt(exts, 0x0010, alpn)

	// key_share 必须是最后一个扩展。
	share := u16(36)
	share = append(share, 0x00, 0x1d)
	share = append(share, u16(len(pub))...)
	share = append(share, pub...)
	exts = appendExt(exts, 0x0033, share)

	body := make([]byte, 4, 4+2+32+1+32+2+6+1+1+2+len(exts))
	body[0] = hsClientHello
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, u16(6)...)
	body = append(body, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)
	body = append(body, 1, 0)
	body = append(body, u16(len(exts))...)
	body = append(body, exts...)
	n := len(body) - 4
	body[1], body[2], body[3] = byte(n>>16), byte(n>>8), byte(n)
	return body
}

// parseServerHello 返回服务端的 x25519 key share 和协商的 TLS 1.3 cipher suite。
func parseServerHello(msg []byte) ([]byte, uint16, error) {
	b := msg[4:]
	if len(b) < 35 {
		return nil, 0, errors.New("reality: short server hello")
	}
	pos := 2 + 32 // legacy_version + random
	sidLen := int(b[pos])
	pos++
	if pos+sidLen+4 > len(b) {
		return nil, 0, errors.New("reality: bad server hello session id")
	}
	pos += sidLen
	// cipher_suite（Xray Reality 用伪装站点的套件，可能是 AES-128/256 或 ChaCha20）
	suite := binary.BigEndian.Uint16(b[pos : pos+2])
	pos += 2 + 1 // cipher_suite + compression
	if pos+2 > len(b) {
		return nil, 0, errors.New("reality: bad server hello")
	}
	extLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if pos+extLen > len(b) {
		return nil, 0, errors.New("reality: bad server hello extensions")
	}
	end := pos + extLen
	for pos+4 <= end {
		tag := binary.BigEndian.Uint16(b[pos : pos+2])
		l := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+l > end {
			return nil, 0, errors.New("reality: bad extension length")
		}
		if tag == 0x0033 { // key_share（ServerHello 里是单个 KeyShareEntry）
			data := b[pos : pos+l]
			if len(data) < 4 {
				return nil, 0, errors.New("reality: short key share")
			}
			group := binary.BigEndian.Uint16(data[:2])
			keyLen := int(binary.BigEndian.Uint16(data[2:4]))
			if group != 0x001d || len(data) < 4+keyLen {
				return nil, 0, errors.New("reality: unsupported key share")
			}
			return data[4 : 4+keyLen], suite, nil
		}
		pos += l
	}
	return nil, 0, errors.New("reality: server hello has no x25519 key share")
}

// tls13Suite 描述服务端协商的 TLS 1.3 cipher suite 对应的 hash 与 AEAD 参数。
type tls13Suite struct {
	id       uint16
	hash     func() hash.Hash
	hashSize int
	keyLen   int
}

func suiteFor(id uint16) (*tls13Suite, error) {
	switch id {
	case 0x1301: // TLS_AES_128_GCM_SHA256
		return &tls13Suite{id, sha256.New, sha256.Size, 16}, nil
	case 0x1302: // TLS_AES_256_GCM_SHA384
		return &tls13Suite{id, sha512.New384, sha512.Size384, 32}, nil
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		return &tls13Suite{id, sha256.New, sha256.Size, 32}, nil
	default:
		return nil, fmt.Errorf("reality: unsupported TLS 1.3 cipher suite 0x%04x", id)
	}
}

type handshakeHash struct {
	h hash.Hash
}

func newHandshakeHash(f func() hash.Hash) *handshakeHash { return &handshakeHash{h: f()} }

func (t *handshakeHash) Write(msg []byte) { _, _ = t.h.Write(msg) }

func (t *handshakeHash) Sum() []byte { return t.h.Sum(nil) }

// --- HKDF（标准库没有 hkdf 包，这里用 hmac 实现） --------------------------

func hkdfExtract(f func() hash.Hash, salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, f().Size())
	}
	h := hmac.New(f, salt)
	_, _ = h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, outLen int, f func() hash.Hash) []byte {
	var out []byte
	var prev []byte
	for counter := byte(1); len(out) < outLen; counter++ {
		h := hmac.New(f, prk)
		_, _ = h.Write(prev)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:outLen]
}

func expandLabel(secret []byte, label string, context []byte, outLen int, f func() hash.Hash) []byte {
	full := "tls13 " + label
	data := u16(outLen)
	data = append(data, byte(len(full)))
	data = append(data, full...)
	data = append(data, byte(len(context)))
	data = append(data, context...)
	return hkdfExpand(secret, data, outLen, f)
}

func hmacMAC(key, data []byte, hf func() hash.Hash) []byte {
	h := hmac.New(hf, key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// --- 密钥调度 ---------------------------------------------------------------

type trafficKey struct {
	secret []byte
	key    []byte
	iv     []byte
	seq    uint64
	aead   cipher.AEAD
}

func newTrafficKey(secret []byte, suite *tls13Suite) (*trafficKey, error) {
	key := expandLabel(secret, "key", nil, suite.keyLen, suite.hash)
	iv := expandLabel(secret, "iv", nil, 12, suite.hash)
	var aead cipher.AEAD
	if suite.id == 0x1303 {
		// ChaCha20-Poly1305（标准库无导出，交给专门的构造函数）
		var err error
		aead, err = quicproto.NewChaCha20Poly1305(key)
		if err != nil {
			return nil, err
		}
	} else {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	}
	return &trafficKey{secret: secret, key: key, iv: iv, aead: aead}, nil
}

func keySchedule(shared, helloHash []byte, suite *tls13Suite) ([]byte, *trafficKey, *trafficKey, error) {
	hs := suite.hashSize
	zeros := make([]byte, hs)
	early := hkdfExtract(suite.hash, nil, zeros)
	emptyHash := suite.hash().Sum(nil)
	derived := expandLabel(early, "derived", emptyHash, hs, suite.hash)
	hsSecret := hkdfExtract(suite.hash, derived, shared)
	cHsSecret := expandLabel(hsSecret, "c hs traffic", helloHash, hs, suite.hash)
	sHsSecret := expandLabel(hsSecret, "s hs traffic", helloHash, hs, suite.hash)
	cHs, err := newTrafficKey(cHsSecret, suite)
	if err != nil {
		return nil, nil, nil, err
	}
	sHs, err := newTrafficKey(sHsSecret, suite)
	if err != nil {
		return nil, nil, nil, err
	}
	return hsSecret, cHs, sHs, nil
}

func applicationKeys(hsSecret, transcript []byte, suite *tls13Suite) (*trafficKey, *trafficKey, error) {
	hs := suite.hashSize
	emptyHash := suite.hash().Sum(nil)
	derived := expandLabel(hsSecret, "derived", emptyHash, hs, suite.hash)
	master := hkdfExtract(suite.hash, derived, make([]byte, hs))
	c := expandLabel(master, "c ap traffic", transcript, hs, suite.hash)
	s := expandLabel(master, "s ap traffic", transcript, hs, suite.hash)
	cKey, err := newTrafficKey(c, suite)
	if err != nil {
		return nil, nil, err
	}
	sKey, err := newTrafficKey(s, suite)
	if err != nil {
		return nil, nil, err
	}
	return cKey, sKey, nil
}

func (t *trafficKey) nonce() []byte {
	nonce := append([]byte(nil), t.iv...)
	for i := 0; i < 8; i++ {
		nonce[12-8+i] ^= byte(t.seq >> (56 - 8*i))
	}
	return nonce
}

func (t *trafficKey) encrypt(inner byte, plain []byte) []byte {
	msg := append(append([]byte(nil), plain...), inner)
	outLen := len(msg) + t.aead.Overhead()
	aad := []byte{recordAppData, 0x03, 0x03, byte(outLen >> 8), byte(outLen)}
	ct := t.aead.Seal(nil, t.nonce(), msg, aad)
	t.seq++
	return ct
}

func (t *trafficKey) decrypt(aad, ct []byte) (byte, []byte, error) {
	plain, err := t.aead.Open(nil, t.nonce(), ct, aad)
	if err != nil {
		return 0, nil, err
	}
	t.seq++
	if len(plain) == 0 {
		return 0, nil, errors.New("reality: empty decrypted record")
	}
	inner := plain[len(plain)-1]
	return inner, plain[:len(plain)-1], nil
}

// --- 记录层 ---------------------------------------------------------------

func readRecord(conn net.Conn) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > 1<<16 {
		return 0, nil, errors.New("reality: oversized record")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	if header[0] == recordAlert {
		return 0, nil, fmt.Errorf("reality: TLS alert %x", payload)
	}
	return header[0], payload, nil
}

func writeRecord(conn net.Conn, typ byte, payload []byte) error {
	header := []byte{typ, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
	buf := net.Buffers{header, payload}
	_, err := buf.WriteTo(conn)
	return err
}

// readServerFlight 读取 EncryptedExtensions / Certificate / CertificateVerify / Finished。
// Reality 会在握手记录末尾夹带填充字节，因此每条记录独立解析，只处理可识别的握手消息。
func readServerFlight(conn net.Conn, sHs *trafficKey, transcript *handshakeHash, authKey []byte, suite *tls13Suite) (ed25519.PublicKey, error) {
	var certPub ed25519.PublicKey
	for {
		typ, payload, err := readRecord(conn)
		if err != nil {
			return nil, err
		}
		if typ == recordCCS {
			continue
		}
		if typ != recordAppData {
			return nil, fmt.Errorf("reality: unexpected record type %d", typ)
		}
		inner, plain, err := sHs.decrypt([]byte{recordAppData, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}, payload)
		if err != nil {
			return nil, fmt.Errorf("reality: decrypt handshake: %w", err)
		}
		if inner != innerHandshake && !isHandshakeMessage(plain) {
			continue
		}
		done, pub, err := processServerMessages(plain, sHs, transcript, authKey, certPub, suite)
		if err != nil {
			return nil, err
		}
		certPub = pub
		if done {
			return certPub, nil
		}
	}
}

// processServerMessages 解析单条记录里的握手消息；无法识别的尾部视为 Reality 填充并丢弃。
func processServerMessages(plain []byte, sHs *trafficKey, transcript *handshakeHash, authKey []byte, certPub ed25519.PublicKey, suite *tls13Suite) (bool, ed25519.PublicKey, error) {
	for len(plain) >= 4 {
		if !isKnownHandshakeType(plain[0]) {
			break
		}
		length := int(plain[1])<<16 | int(plain[2])<<8 | int(plain[3])
		if len(plain) < 4+length {
			break
		}
		msg := plain[:4+length]
		plain = plain[4+length:]
		switch msg[0] {
		case hsNewSessionTicket, hsEncryptedExtensions:
			transcript.Write(msg)
		case hsCertificate:
			pub, err := verifyRealityCertificate(msg, authKey)
			if err != nil {
				return false, nil, err
			}
			certPub = pub
			transcript.Write(msg)
		case hsCertificateVerify:
			if certPub == nil {
				return false, nil, errors.New("reality: certificate verify before certificate")
			}
			if err := verifyCertificateVerify(msg, certPub, transcript.Sum()); err != nil {
				return false, nil, err
			}
			transcript.Write(msg)
		case hsFinished:
			key := expandLabel(sHs.secret, "finished", nil, suite.hashSize, suite.hash)
			if !hmac.Equal(hmacMAC(key, transcript.Sum(), suite.hash), msg[4:]) {
				return false, nil, errors.New("reality: bad server Finished")
			}
			transcript.Write(msg)
			if certPub == nil {
				return false, nil, errors.New("reality: server did not send certificate")
			}
			return true, certPub, nil
		}
	}
	return false, certPub, nil
}

// 测试时跳过 Reality 证书 HMAC 校验，用于和 crypto/tls 服务端互通验证。
var skipCertVerifyForTest bool

func isHandshakeMessage(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	switch p[0] {
	case hsNewSessionTicket, hsEncryptedExtensions, hsCertificate, hsCertificateVerify, hsFinished:
		return true
	default:
		return false
	}
}

func isKnownHandshakeType(t byte) bool {
	switch t {
	case hsNewSessionTicket, hsEncryptedExtensions, hsCertificate, hsCertificateVerify, hsFinished:
		return true
	default:
		return false
	}
}

func verifyRealityCertificate(msg []byte, authKey []byte) (ed25519.PublicKey, error) {
	b := msg[4:]
	if len(b) < 4 {
		return nil, errors.New("reality: short certificate message")
	}
	pos := 1 + int(b[0])
	if pos+3 > len(b) {
		return nil, errors.New("reality: bad certificate list")
	}
	listLen := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
	pos += 3
	if pos+listLen > len(b) || listLen < 3 {
		return nil, errors.New("reality: bad certificate list length")
	}
	certLen := int(b[pos])<<16 | int(b[pos+1])<<8 | int(b[pos+2])
	pos += 3
	if pos+certLen > len(b) {
		return nil, errors.New("reality: bad certificate length")
	}
	cert, err := x509.ParseCertificate(b[pos : pos+certLen])
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("reality: certificate is not Ed25519")
	}
	if !skipCertVerifyForTest {
		h := hmac.New(sha512.New, authKey)
		_, _ = h.Write(pub)
		if !hmac.Equal(h.Sum(nil), cert.Signature) {
			return nil, errors.New("reality: authentication failed")
		}
	}
	return pub, nil
}

func verifyCertificateVerify(msg []byte, pub ed25519.PublicKey, transcript []byte) error {
	b := msg[4:]
	if len(b) < 4 {
		return errors.New("reality: short certificate verify")
	}
	alg := binary.BigEndian.Uint16(b[:2])
	sigLen := int(binary.BigEndian.Uint16(b[2:4]))
	if alg != 0x0807 || len(b) < 4+sigLen {
		return errors.New("reality: unsupported certificate verify")
	}
	signed := make([]byte, 0, 64+34+1+len(transcript))
	signed = append(signed, bytes.Repeat([]byte{0x20}, 64)...)
	signed = append(signed, []byte("TLS 1.3, server CertificateVerify")...)
	signed = append(signed, 0)
	signed = append(signed, transcript...)
	if !ed25519.Verify(pub, signed, b[4:4+sigLen]) {
		return errors.New("reality: bad certificate verify")
	}
	return nil
}

// tls13Conn 用应用数据密钥包装原始 TCP 连接。
type tls13Conn struct {
	net.Conn
	in      *trafficKey
	out     *trafficKey
	readBuf []byte
}

// RawConn 返回外层 TLS 之下的裸 TCP 连接（供 XTLS Vision direct 模式绕过加密用）。
func (c *tls13Conn) RawConn() net.Conn { return c.Conn }

// TakeReadBuf 取出并返回已解密但未被读取的明文缓冲（direct 切换时避免丢数据）。
func (c *tls13Conn) TakeReadBuf() []byte {
	b := c.readBuf
	c.readBuf = nil
	return b
}

func (c *tls13Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		typ, payload, err := readRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		if typ == recordCCS {
			continue
		}
		if typ != recordAppData {
			return 0, fmt.Errorf("reality: unexpected application record %d", typ)
		}
		inner, plain, err := c.in.decrypt([]byte{recordAppData, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}, payload)
		if err != nil {
			return 0, fmt.Errorf("reality: decrypt application data: %w", err)
		}
		if inner == innerAppData && len(plain) > 0 {
			c.readBuf = plain
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		// NewSessionTicket 等握手消息在应用数据阶段直接忽略。
	}
}

func (c *tls13Conn) Write(p []byte) (int, error) {
	const maxRecord = 16384
	total := len(p)
	for len(p) > 0 {
		n := len(p)
		if n > maxRecord {
			n = maxRecord
		}
		if err := writeRecord(c.Conn, recordAppData, c.out.encrypt(innerAppData, p[:n])); err != nil {
			return 0, err
		}
		p = p[n:]
	}
	return total, nil
}
