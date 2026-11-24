// Package vproto implements the VLESS and VMess (AEAD / AES-128-GCM) client
// handshakes using only the Go standard library.
//
// It is intended as a drop-in, dependency-free replacement for the protocol
// layer of github.com/metacubex/sing-vmess. Transport concerns (TCP, TLS,
// WebSocket, ...) are deliberately left to the caller: DialConn writes the
// protocol header onto an already established net.Conn and returns a
// connection whose Read/Write carry the proxied payload.
//
// No third-party packages are imported (in particular no golang.org/x/*).
// SHAKE128, needed for VMess AEAD chunk masking, comes from the standard
// library package crypto/sha3 (available since Go 1.24).
package vproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Common helpers
// ---------------------------------------------------------------------------

// parseUUID parses a canonical UUID string (with or without dashes/braces)
// into its 16-byte binary representation.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	cleaned := strings.ReplaceAll(s, "-", "")
	cleaned = strings.TrimPrefix(cleaned, "{")
	cleaned = strings.TrimSuffix(cleaned, "}")
	if len(cleaned) != 32 {
		return out, fmt.Errorf("vproto: invalid UUID %q: want 32 hex digits", s)
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return out, fmt.Errorf("vproto: invalid UUID %q: %w", s, err)
	}
	copy(out[:], b)
	return out, nil
}

// appendTargetAddr appends the VMess/VLESS address encoding used by
// sing-vmess: the 2-byte big-endian port comes FIRST, followed by the address
// type byte and the address itself.
//
// Address types: 0x01 = IPv4, 0x02 = domain name, 0x03 = IPv6.
func appendTargetAddr(dst []byte, host string, port uint16) ([]byte, error) {
	dst = append(dst, byte(port>>8), byte(port))
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			dst = append(dst, 0x01)
			dst = append(dst, ip4...)
		} else {
			dst = append(dst, 0x03)
			dst = append(dst, ip.To16()...)
		}
		return dst, nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("vproto: host name too long (%d bytes)", len(host))
	}
	dst = append(dst, 0x02, byte(len(host)))
	dst = append(dst, host...)
	return dst, nil
}

// ===========================================================================
// VLESS
// ===========================================================================

const (
	vlessVersion       = 0
	vlessCmdTCP        = 1
	vlessCmdUDP        = 2
	vlessFlowVision    = "xtls-rprx-vision"
	vlessAddonsFlowTag = byte(1<<3 | 2) // protobuf field 1, wire type 2 (length-delimited)
)

// VLESSClient holds the credentials for a VLESS outbound.
//
// VLESS itself is unencrypted: it is expected to run over TLS / WebSocket /
// another secure transport. Flow is encoded into the VLESS addons field.
type VLESSClient struct {
	UUID [16]byte
	Flow string
}

// NewVLESSClient parses uuidStr (a canonical UUID string) and creates a VLESS
// client. An empty flow means no addons; the recognised flow name is
// "xtls-rprx-vision" (the header is encoded correctly; the TLS-level XTLS
// Vision traffic filtering itself is a transport-layer feature and is not
// implemented here).
func NewVLESSClient(uuidStr, flow string) (*VLESSClient, error) {
	u, err := parseUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	return &VLESSClient{UUID: u, Flow: flow}, nil
}

// DialConn writes the VLESS request header to conn and returns a connection
// for forwarding raw payload bytes. The returned value is a thin wrapper
// around conn: on the first Read it consumes the 2-byte VLESS response header
// ([version][addonsLen][addons...]), which some servers send immediately and
// others prepend to their first data write. Write passes straight through.
//
// If isUDP is true the request uses command 2 (UDP); payloads must then be
// framed as [2-byte big-endian length][packet] in both directions, as
// required by VLESS UDP.
// DialConnWithHeaderWriter 与 DialConn 相同，但 VLESS 请求头写到 headerConn，
// 返回的连接的读写走 dataConn。用于 XTLS Vision：header 必须直写底层
// （出现在 Vision 帧之前），应用数据才走 Vision padding。
func (c *VLESSClient) DialConnWithHeaderWriterEx(headerConn, dataConn net.Conn, host string, port uint16, isUDP bool, afterHeader func() error) (net.Conn, error) {
	if headerConn == nil || dataConn == nil {
		return nil, errors.New("vproto: nil connection")
	}
	header := make([]byte, 0, 1+16+1+1+len(c.Flow)+1+2+1+len(host)+2)
	header = append(header, vlessVersion)
	header = append(header, c.UUID[:]...)
	var addons []byte
	if c.Flow != "" {
		var uvarint [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(uvarint[:], uint64(len(c.Flow)))
		addons = append(addons, vlessAddonsFlowTag)
		addons = append(addons, uvarint[:n]...)
		addons = append(addons, c.Flow...)
	}
	if len(addons) > 255 {
		return nil, fmt.Errorf("vproto: VLESS addons too long (%d bytes)", len(addons))
	}
	header = append(header, byte(len(addons)))
	header = append(header, addons...)
	if isUDP {
		header = append(header, vlessCmdUDP)
	} else {
		header = append(header, vlessCmdTCP)
	}
	var err error
	header, err = appendTargetAddr(header, host, port)
	if err != nil {
		return nil, err
	}
	if _, err := headerConn.Write(header); err != nil {
		return nil, fmt.Errorf("vproto: write VLESS request: %w", err)
	}
	// Vision 握手：header 后立刻发空帧（带 UUID + padding）。
	if afterHeader != nil {
		if err := afterHeader(); err != nil {
			return nil, fmt.Errorf("vproto: after header: %w", err)
		}
	}
	// 响应头由 vlessConn 首次 Read 时 lazy 读取；dataConn（Vision 包装）
	// 会在首次 Read 前透传这 2 字节 VLESS 响应头。
	return &vlessConn{Conn: dataConn}, nil
}

func (c *VLESSClient) DialConn(conn net.Conn, host string, port uint16, isUDP bool) (net.Conn, error) {
	if conn == nil {
		return nil, errors.New("vproto: nil connection")
	}

	header := make([]byte, 0, 1+16+1+1+len(c.Flow)+1+2+1+len(host)+2)
	header = append(header, vlessVersion)
	header = append(header, c.UUID[:]...)

	// Addons: a minimal protobuf message carrying the flow name.
	var addons []byte
	if c.Flow != "" {
		var uvarint [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(uvarint[:], uint64(len(c.Flow)))
		addons = append(addons, vlessAddonsFlowTag)
		addons = append(addons, uvarint[:n]...)
		addons = append(addons, c.Flow...)
	}
	if len(addons) > 255 {
		return nil, fmt.Errorf("vproto: VLESS addons too long (%d bytes)", len(addons))
	}
	header = append(header, byte(len(addons)))
	header = append(header, addons...)

	if isUDP {
		header = append(header, vlessCmdUDP)
	} else {
		header = append(header, vlessCmdTCP)
	}
	var err error
	header, err = appendTargetAddr(header, host, port)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(header); err != nil {
		return nil, fmt.Errorf("vproto: write VLESS request: %w", err)
	}
	return &vlessConn{Conn: conn}, nil
}

// vlessConn consumes the VLESS response header lazily on the first Read. VLESS
// does not encrypt the payload, so Write is a plain pass-through.
type vlessConn struct {
	net.Conn
	readOnce       sync.Once
	readErr        error
	headerConsumed bool // VLESS 响应头已在外部读取（Vision 场景）
}

func (c *vlessConn) Read(p []byte) (int, error) {
	if c.headerConsumed {
		return c.Conn.Read(p)
	}
	c.readOnce.Do(func() {
		// Response: [version][addonsLen][addons...].
		var resp [2]byte
		if _, err := io.ReadFull(c.Conn, resp[:]); err != nil {
			c.readErr = fmt.Errorf("vproto: read VLESS response: %w", err)
			return
		}
		if resp[0] != vlessVersion {
			c.readErr = fmt.Errorf("vproto: unexpected VLESS response version %d", resp[0])
			return
		}
		if resp[1] > 0 {
			if _, err := io.CopyN(io.Discard, c.Conn, int64(resp[1])); err != nil {
				c.readErr = fmt.Errorf("vproto: read VLESS response addons: %w", err)
			}
		}
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}

// ===========================================================================
// VMess (AEAD, AES-128-GCM)
// ===========================================================================

const (
	vmessVersion        = 1
	vmessSecurityLegacy = 1 // AES-128-CFB (alterId / legacy header)
	vmessSecurityGCM    = 3 // AES-128-GCM
	vmessSecurityChacha = 4 // ChaCha20-Poly1305

	vmessCmdTCP = 1
	vmessCmdUDP = 2

	vmessOptChunkStream  = 1
	vmessOptChunkMasking = 4

	vmessChunkOverhead = 16 // AES-GCM authentication tag size
	vmessWriteChunk    = 15000
)

// VMess KDF salt constants.
const (
	kdfSaltVMessKDF = "VMess AEAD KDF"

	kdfSaltAuthIDEncryption = "AES Auth ID Encryption"

	kdfSaltHeaderKey     = "VMess Header AEAD Key"
	kdfSaltHeaderIV      = "VMess Header AEAD Nonce"
	kdfSaltHeaderLenKey  = "VMess Header AEAD Key_Length"
	kdfSaltHeaderLenIV   = "VMess Header AEAD Nonce_Length"
	kdfSaltRespHeaderKey = "AEAD Resp Header Key"
	kdfSaltRespHeaderIV  = "AEAD Resp Header IV"
	kdfSaltRespLenKey    = "AEAD Resp Header Len Key"
	kdfSaltRespLenIV     = "AEAD Resp Header Len IV"
)

// Error values returned by this package.
var (
	ErrUnsupportedSecurity = errors.New("vproto: unsupported VMess security")
	ErrBadVMessResponse    = errors.New("vproto: bad VMess response")
	ErrBadChunkLength      = errors.New("vproto: bad VMess chunk length")
)

// hmacCreator models the nested-HMAC construction used by the VMess KDF.
type hmacCreator struct {
	parent *hmacCreator
	value  []byte
}

func (h *hmacCreator) create() hash.Hash {
	if h.parent == nil {
		return hmac.New(sha256.New, h.value)
	}
	return hmac.New(h.parent.create, h.value)
}

// kdf implements the VMess AEAD key derivation function:
//
//	nested HMAC-SHA256 with keys ["VMess AEAD KDF", salt, path...],
//	message = key.
func kdf(key []byte, salt string, path ...[]byte) []byte {
	c := &hmacCreator{value: []byte(kdfSaltVMessKDF)}
	c = &hmacCreator{value: []byte(salt), parent: c}
	for _, p := range path {
		c = &hmacCreator{value: p, parent: c}
	}
	h := c.create()
	_, _ = h.Write(key)
	return h.Sum(nil)
}

// vmessKey derives the 16-byte AEAD user key from the UUID.
func vmessKey(uuid [16]byte) (key [16]byte) {
	h := md5.New()
	_, _ = h.Write(uuid[:])
	_, _ = h.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	h.Sum(key[:0])
	return
}

func newAESGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("vproto: aes.NewCipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("vproto: cipher.NewGCM: " + err.Error())
	}
	return aead
}

// buildAuthID produces the 16-byte VMess AEAD authentication header:
// [8-byte timestamp][4-byte random][4-byte CRC32 of the first 12 bytes],
// encrypted with AES-128-ECB using KDF(key, "AES Auth ID Encryption").
func buildAuthID(key [16]byte, t time.Time) ([16]byte, error) {
	var authID [16]byte
	binary.BigEndian.PutUint64(authID[0:8], uint64(t.Unix()))
	if _, err := io.ReadFull(rand.Reader, authID[8:12]); err != nil {
		return authID, err
	}
	binary.BigEndian.PutUint32(authID[12:16], crc32.ChecksumIEEE(authID[0:12]))
	block, err := aes.NewCipher(kdf(key[:], kdfSaltAuthIDEncryption)[:16])
	if err != nil {
		return authID, err
	}
	block.Encrypt(authID[:], authID[:])
	return authID, nil
}

// nextMaskUint16 draws the next 2 bytes of a SHAKE128 mask as a big-endian
// uint16 (used for VMess chunk-length masking).
func nextMaskUint16(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// VMessClient holds the credentials for a VMess outbound. It supports both
// the modern AEAD modes (AES-128-GCM / ChaCha20-Poly1305) and the legacy
// AES-128-CFB mode used together with alterId.
type VMessClient struct {
	UUID     [16]byte
	Security string

	key      [16]byte
	security byte
	alterId  int
	alterKey [16]byte
}

// NewVMessClient creates a VMess client with alterId = 0. Supported security
// names are "aes-128-gcm" (the default), "chacha20-poly1305" and
// "aes-128-cfb" (legacy stream cipher). "auto" and "" resolve to
// AES-128-GCM on this platform.
func NewVMessClient(uuidStr, security string) (*VMessClient, error) {
	return NewVMessClientWithAlterId(uuidStr, security, 0)
}

// NewVMessClientWithAlterId creates a VMess client with an explicit alterId.
// A positive alterId switches the handshake to the legacy format (16-byte
// HMAC-MD5 timestamp tag plus a CFB-encrypted header); if security is
// unspecified or "aes-128-gcm", it is automatically changed to the legacy
// "aes-128-cfb" stream cipher, which is what alterId is normally used with.
func NewVMessClientWithAlterId(uuidStr, security string, alterId int) (*VMessClient, error) {
	if alterId < 0 {
		return nil, errors.New("vproto: negative VMess alterId")
	}
	u, err := parseUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	var sec byte
	switch strings.ToLower(security) {
	case "", "auto":
		sec = vmessSecurityGCM
	case "aes-128-gcm", "gcm":
		sec = vmessSecurityGCM
	case "chacha20-poly1305", "chacha20-ietf-poly1305", "chacha":
		sec = vmessSecurityChacha
	case "aes-128-cfb", "cfb", "legacy":
		sec = vmessSecurityLegacy
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedSecurity, security)
	}
	// alterId is a legacy concept: default the stream cipher to AES-128-CFB.
	if alterId > 0 && sec == vmessSecurityGCM &&
		(security == "" || strings.EqualFold(security, "auto") || strings.EqualFold(security, "aes-128-gcm")) {
		sec = vmessSecurityLegacy
	}
	c := &VMessClient{
		UUID:     u,
		Security: security,
		key:      vmessKey(u),
		security: sec,
		alterId:  alterId,
	}
	if alterId > 0 {
		c.alterKey = vmessAlterKey(u)
	}
	return c, nil
}

// newStreamAEAD returns the AEAD used for the payload chunk stream. AES-128-GCM
// uses the 16-byte request key directly; ChaCha20-Poly1305 derives a 32-byte
// key from it exactly like sing-vmess / v2ray do.
func newStreamAEAD(security byte, key, nonce []byte) cipher.AEAD {
	if security == vmessSecurityChacha {
		return newChacha20Poly1305Must(GenerateChacha20Poly1305Key(key))
	}
	return newAESGCM(key)
}

func newChacha20Poly1305Must(key []byte) cipher.AEAD {
	aead, err := newChacha20Poly1305(key, false)
	if err != nil {
		panic("vproto: newChacha20Poly1305: " + err.Error())
	}
	return aead
}

// GenerateChacha20Poly1305Key expands a 16-byte VMess request key into the
// 32-byte key required by ChaCha20-Poly1305:
//
//	key = MD5(input) || MD5(MD5(input)[:16])
func GenerateChacha20Poly1305Key(b []byte) []byte {
	key := make([]byte, 32)
	checksum := md5.Sum(b)
	copy(key, checksum[:])
	checksum = md5.Sum(key[:16])
	copy(key[16:], checksum[:])
	return key
}

// DialConn writes a VMess request header to conn and returns a net.Conn
// wrapper that transparently encrypts/decrypts the payload. The handshake
// format is chosen automatically: alterId > 0 uses the legacy timestamp/MD5
// header, otherwise the AEAD header is used. The payload cipher is selected
// by the security string (AES-128-GCM, ChaCha20-Poly1305 or AES-128-CFB).
// The response header is consumed lazily on the first Read.
func (c *VMessClient) DialConn(conn net.Conn, host string, port uint16) (net.Conn, error) {
	return c.dial(conn, host, port, vmessCmdTCP)
}

func (c *VMessClient) dial(conn net.Conn, host string, port uint16, command byte) (net.Conn, error) {
	if conn == nil {
		return nil, errors.New("vproto: nil connection")
	}

	var requestKey, requestNonce [16]byte
	if _, err := io.ReadFull(rand.Reader, requestKey[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, requestNonce[:]); err != nil {
		return nil, err
	}
	var responseHeader [1]byte
	if _, err := io.ReadFull(rand.Reader, responseHeader[:]); err != nil {
		return nil, err
	}
	var paddingRandom [1]byte
	if _, err := io.ReadFull(rand.Reader, paddingRandom[:]); err != nil {
		return nil, err
	}
	paddingLen := int(paddingRandom[0] & 0x0f)

	// The legacy stream cipher does not mask chunk lengths; AEAD streams do.
	option := byte(vmessOptChunkStream)
	if c.security != vmessSecurityLegacy {
		option |= vmessOptChunkMasking
	}

	// ---- Build the plaintext request header. ----
	header := make([]byte, 0, 1+16+16+1+1+1+1+1+2+1+len(host)+paddingLen+4)
	header = append(header, vmessVersion)
	header = append(header, requestNonce[:]...) // NOTE: nonce first, then key
	header = append(header, requestKey[:]...)
	header = append(header, responseHeader[0])
	header = append(header, option)
	header = append(header, byte(paddingLen<<4)|c.security)
	header = append(header, 0x00) // reserved
	header = append(header, command)
	header, err := appendTargetAddr(header, host, port)
	if err != nil {
		return nil, err
	}
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return nil, err
		}
		header = append(header, padding...)
	}
	h := fnv.New32a()
	_, _ = h.Write(header)
	header = append(header,
		byte(h.Sum32()>>24), byte(h.Sum32()>>16), byte(h.Sum32()>>8), byte(h.Sum32()))

	// ---- Write the handshake. ----
	if c.alterId > 0 {
		// Legacy header: [16-byte HMAC-MD5 timestamp tag][CFB-encrypted header].
		timestamp := time.Now().Unix()
		idHash := vmessLegacyIDHash(c.alterKey, timestamp)
		timeIV := vmessLegacyTimeIV(timestamp)
		headerCipher, err := newCFBEncrypter128(c.key[:], timeIV[:])
		if err != nil {
			return nil, err
		}
		encHeader := make([]byte, len(header))
		headerCipher.XORKeyStream(encHeader, header)
		request := make([]byte, 0, len(idHash)+len(encHeader))
		request = append(request, idHash[:]...)
		request = append(request, encHeader...)
		if _, err := conn.Write(request); err != nil {
			return nil, fmt.Errorf("vproto: write VMess legacy handshake: %w", err)
		}
	} else {
		// AEAD header: AuthID + encrypted length + connection nonce + header.
		authID, err := buildAuthID(c.key, time.Now())
		if err != nil {
			return nil, err
		}
		var connectionNonce [8]byte
		if _, err := io.ReadFull(rand.Reader, connectionNonce[:]); err != nil {
			return nil, err
		}

		lengthKey := kdf(c.key[:], kdfSaltHeaderLenKey, authID[:], connectionNonce[:])[:16]
		lengthNonce := kdf(c.key[:], kdfSaltHeaderLenIV, authID[:], connectionNonce[:])[:12]
		headerKey := kdf(c.key[:], kdfSaltHeaderKey, authID[:], connectionNonce[:])[:16]
		headerNonce := kdf(c.key[:], kdfSaltHeaderIV, authID[:], connectionNonce[:])[:12]

		// Encrypted header length (2 bytes plaintext + 16-byte tag), AAD = authID.
		var encLen [2 + vmessChunkOverhead]byte
		binary.BigEndian.PutUint16(encLen[0:2], uint16(len(header)))
		newAESGCM(lengthKey).Seal(encLen[:0], lengthNonce, encLen[0:2], authID[:])

		// Encrypted header, AAD = authID.
		encrypted := newAESGCM(headerKey).Seal(nil, headerNonce, header, authID[:])

		request := make([]byte, 0, len(authID)+len(encLen)+len(connectionNonce)+len(encrypted))
		request = append(request, authID[:]...)
		request = append(request, encLen[:]...)
		request = append(request, connectionNonce[:]...)
		request = append(request, encrypted...)
		if _, err := conn.Write(request); err != nil {
			return nil, fmt.Errorf("vproto: write VMess handshake: %w", err)
		}
	}

	// ---- Set up the data-stream cryptor. ----
	vc := &vmessConn{
		Conn:           conn,
		security:       c.security,
		alterIDHeader:  c.alterId > 0,
		requestKey:     requestKey,
		requestNonce:   requestNonce,
		responseHeader: responseHeader[0],
	}
	if c.security == vmessSecurityLegacy {
		vc.writeCFB, err = newCFBEncrypter128(requestKey[:], requestNonce[:])
		if err != nil {
			return nil, err
		}
	} else {
		aead := newStreamAEAD(c.security, requestKey[:], requestNonce[:])
		writeNonce := make([]byte, aead.NonceSize())
		copy(writeNonce, requestNonce[:]) // first 12 bytes of the 16-byte IV
		writeMask := sha3.NewSHAKE128()
		_, _ = writeMask.Write(requestNonce[:])
		vc.writeAEAD = aead
		vc.writeNonce = writeNonce
		vc.writeMask = writeMask
	}
	return vc, nil
}

// vmessConn wraps the transport connection with VMess payload encryption.
// Both the AEAD (AES-128-GCM / ChaCha20-Poly1305) and the legacy AES-128-CFB
// chunk streams are supported; the choice is stored in security.
type vmessConn struct {
	net.Conn

	security      byte
	alterIDHeader bool

	requestKey     [16]byte
	requestNonce   [16]byte
	responseHeader byte

	// write state
	writeMu    sync.Mutex
	writeAEAD  cipher.AEAD
	writeCFB   cipher.Stream
	writeNonce []byte // AEAD nonce; first 2 bytes hold the counter
	writeCount uint16
	writeMask  io.Reader // SHAKE128 seeded with requestNonce

	// read state
	readOnce    sync.Once
	readInitErr error
	readStream  io.Reader // underlying stream for payload frames
	readAEAD    cipher.AEAD
	readNonce   []byte // AEAD nonce; first 2 bytes hold the counter
	readCount   uint16
	readMask    io.Reader // SHAKE128 seeded with responseNonce
	readBuf     []byte
	readOff     int
	readMu      sync.Mutex
}

// initReader lazily consumes the response header and prepares the read
// direction. A legacy (alterId) response header is a 4-byte CFB-encrypted
// block; an AEAD response header is a pair of AES-GCM encrypted envelopes.
func (c *vmessConn) initReader() error {
	c.readOnce.Do(func() {
		if c.alterIDHeader {
			key, iv := vmessResponseLegacyKeys(c.requestKey, c.requestNonce)
			reader, err := newCFBReader(c.Conn, key[:], iv[:])
			if err != nil {
				c.readInitErr = err
				return
			}
			var resp [4]byte
			if _, err := io.ReadFull(reader, resp[:]); err != nil {
				c.readInitErr = fmt.Errorf("vproto: read VMess legacy response: %w", err)
				return
			}
			if resp[0] != c.responseHeader {
				c.readInitErr = fmt.Errorf("%w: legacy response header mismatch", ErrBadVMessResponse)
				return
			}
			// The command bytes, when present, belong to the same CFB stream.
			if cmdLen := int(resp[3]); cmdLen > 0 {
				if _, err := io.CopyN(io.Discard, reader, int64(cmdLen)); err != nil {
					c.readInitErr = fmt.Errorf("vproto: read VMess legacy response command: %w", err)
					return
				}
			}
			c.readStream = reader
			return
		}

		responseKey := sha256.Sum256(c.requestKey[:])
		respKey := responseKey[:16]
		responseNonceHash := sha256.Sum256(c.requestNonce[:])
		respNonce := responseNonceHash[:16]

		lenKey := kdf(respKey, kdfSaltRespLenKey)[:16]
		lenIV := kdf(respNonce, kdfSaltRespLenIV)[:12]
		headerKey := kdf(respKey, kdfSaltRespHeaderKey)[:16]
		headerIV := kdf(respNonce, kdfSaltRespHeaderIV)[:12]

		var encLen [2 + vmessChunkOverhead]byte
		if _, err := io.ReadFull(c.Conn, encLen[:]); err != nil {
			c.readInitErr = fmt.Errorf("vproto: read VMess response header length: %w", err)
			return
		}
		plainLen, err := newAESGCM(lenKey).Open(nil, lenIV, encLen[:], nil)
		if err != nil || len(plainLen) != 2 {
			c.readInitErr = fmt.Errorf("%w: response header length: %v", ErrBadVMessResponse, err)
			return
		}
		headerLen := int(binary.BigEndian.Uint16(plainLen))

		encHeader := make([]byte, headerLen+vmessChunkOverhead)
		if _, err := io.ReadFull(c.Conn, encHeader); err != nil {
			c.readInitErr = fmt.Errorf("vproto: read VMess response header: %w", err)
			return
		}
		header, err := newAESGCM(headerKey).Open(nil, headerIV, encHeader, nil)
		if err != nil {
			c.readInitErr = fmt.Errorf("%w: response header: %v", ErrBadVMessResponse, err)
			return
		}
		if len(header) < 4 || header[0] != c.responseHeader {
			c.readInitErr = fmt.Errorf("%w: response header mismatch", ErrBadVMessResponse)
			return
		}

		c.readStream = c.Conn
		if c.security == vmessSecurityLegacy {
			// Legacy stream cipher with an AEAD header: response keys are the
			// SHA-256-derived ones, but the frames are plain CFB chunks.
			return
		}
		aead := newStreamAEAD(c.security, respKey, respNonce)
		readNonce := make([]byte, aead.NonceSize())
		copy(readNonce, respNonce)
		mask := sha3.NewSHAKE128()
		_, _ = mask.Write(respNonce)

		c.readAEAD = aead
		c.readNonce = readNonce
		c.readMask = mask
	})
	return c.readInitErr
}

// readNextChunk reads and decrypts one payload chunk from the transport.
func (c *vmessConn) readNextChunk() error {
	if c.security == vmessSecurityLegacy {
		return c.readNextLegacyChunk()
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.readStream, lenBuf[:]); err != nil {
		return err
	}
	mask, err := nextMaskUint16(c.readMask)
	if err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(lenBuf[:]) ^ mask)
	if length == 0 {
		return io.EOF
	}
	if length < vmessChunkOverhead {
		return fmt.Errorf("%w: %d", ErrBadChunkLength, length)
	}

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(c.readStream, ciphertext); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(c.readNonce[0:2], c.readCount)
	c.readCount++
	plaintext, err := c.readAEAD.Open(nil, c.readNonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("vproto: decrypt VMess chunk: %w", err)
	}
	c.readBuf = plaintext
	c.readOff = 0
	return nil
}

// Read implements net.Conn. It transparently handles the response header and
// chunk decryption on the first call.
func (c *vmessConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.initReader(); err != nil {
		return 0, err
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.readOff >= len(c.readBuf) {
		if err := c.readNextChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf[c.readOff:])
	c.readOff += n
	return n, nil
}

// Write implements net.Conn. AEAD chunks carry a masked 2-byte big-endian
// length; legacy chunks carry a plain 2-byte length plus a 4-byte FNV1a
// checksum, all covered by the AES-128-CFB stream.
func (c *vmessConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > vmessWriteChunk {
			n = vmessWriteChunk
		}
		if c.security == vmessSecurityLegacy {
			if err := c.writeLegacyFrame(p[:n]); err != nil {
				return written, err
			}
		} else {
			binary.BigEndian.PutUint16(c.writeNonce[0:2], c.writeCount)
			c.writeCount++
			ciphertext := c.writeAEAD.Seal(nil, c.writeNonce, p[:n], nil)

			mask, err := nextMaskUint16(c.writeMask)
			if err != nil {
				return written, err
			}
			frame := make([]byte, 2+len(ciphertext))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(ciphertext))^mask)
			copy(frame[2:], ciphertext)
			if _, err := c.Conn.Write(frame); err != nil {
				return written, err
			}
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
