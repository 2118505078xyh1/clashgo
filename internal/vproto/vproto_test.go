package vproto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"testing"
	"time"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// ---------------------------------------------------------------------------
// Helpers that act as a minimal VMess server, using only standard library
// primitives re-implemented in this package.
// ---------------------------------------------------------------------------

type recordingReader struct {
	r   io.Reader
	buf []byte
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf = append(r.buf, p[:n]...)
	return n, err
}

// readLegacyRequest parses a legacy handshake from conn and returns the
// request body key/IV, response header byte, option, security byte and a CFB
// reader positioned at the start of the client's payload stream.
func readLegacyRequest(t *testing.T, conn net.Conn, uuidStr string, alterId int) ([16]byte, [16]byte, byte, byte, byte, byte) {
	t.Helper()
	u, err := parseUUID(uuidStr)
	if err != nil {
		t.Fatal(err)
	}
	var idHash [16]byte
	if _, err := io.ReadFull(conn, idHash[:]); err != nil {
		t.Fatal(err)
	}
	alterKey := vmessAlterKey(u)
	now := time.Now().Unix()
	var ts int64
	for cand := now - 10; cand <= now+10; cand++ {
		if vmessLegacyIDHash(alterKey, cand) == idHash {
			ts = cand
			break
		}
	}
	if ts == 0 {
		t.Fatalf("legacy idHash did not match any timestamp near %d", now)
	}
	timeIV := vmessLegacyTimeIV(ts)
	userKey := vmessKey(u)
	dec, err := newCFBDecrypter128(userKey[:], timeIV[:])
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingReader{r: conn}
	plain := &cfbReader{upstream: rec, stream: dec}

	var header bytes.Buffer
	var nonce, key [16]byte
	read1 := func() byte {
		var b [1]byte
		if _, err := io.ReadFull(plain, b[:]); err != nil {
			t.Fatal(err)
		}
		return b[0]
	}
	version := read1()
	if _, err := io.ReadFull(plain, nonce[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(plain, key[:]); err != nil {
		t.Fatal(err)
	}
	respHeader := read1()
	option := read1()
	psec := read1()
	reserved := read1()
	command := read1()
	header.WriteByte(version)
	header.Write(nonce[:])
	header.Write(key[:])
	header.WriteByte(respHeader)
	header.WriteByte(option)
	header.WriteByte(psec)
	header.WriteByte(reserved)
	header.WriteByte(command)

	// Address: 2-byte port, 1-byte type, then the address itself.
	var addrBuf [2]byte
	if _, err := io.ReadFull(plain, addrBuf[:]); err != nil {
		t.Fatal(err)
	}
	header.Write(addrBuf[:])
	port := binary.BigEndian.Uint16(addrBuf[:])
	var atype [1]byte
	if _, err := io.ReadFull(plain, atype[:]); err != nil {
		t.Fatal(err)
	}
	header.Write(atype[:])
	switch atype[0] {
	case 0x01: // IPv4
		var ip [4]byte
		io.ReadFull(plain, ip[:])
		header.Write(ip[:])
		if net.IP(ip[:]).String() != "1.2.3.4" {
			t.Fatalf("unexpected IPv4 %v", net.IP(ip[:]))
		}
	case 0x02: // domain
		var n [1]byte
		io.ReadFull(plain, n[:])
		header.Write(n[:])
		domain := make([]byte, n[0])
		io.ReadFull(plain, domain)
		header.Write(domain)
	case 0x03: // IPv6
		var ip [16]byte
		io.ReadFull(plain, ip[:])
		header.Write(ip[:])
	default:
		t.Fatalf("unexpected address type %d", atype[0])
	}
	if port != 443 {
		t.Fatalf("unexpected port %d", port)
	}

	padding := int(psec >> 4)
	if padding > 0 {
		pad := make([]byte, padding)
		if _, err := io.ReadFull(plain, pad); err != nil {
			t.Fatal(err)
		}
		header.Write(pad)
	}
	var hash [4]byte
	if _, err := io.ReadFull(plain, hash[:]); err != nil {
		t.Fatal(err)
	}
	h := fnv.New32a()
	h.Write(header.Bytes())
	if h.Sum32() != binary.BigEndian.Uint32(hash[:]) {
		t.Fatal("legacy header checksum mismatch")
	}
	return key, nonce, respHeader, psec & 0x0f, option, command
}

// readAEADHandshake parses a modern AEAD handshake and returns the decrypted
// request body key/IV, response header byte, option, security and command.
func readAEADHandshake(t *testing.T, conn net.Conn, uuidStr string) ([16]byte, [16]byte, byte, byte, byte, byte) {
	t.Helper()
	u, err := parseUUID(uuidStr)
	if err != nil {
		t.Fatal(err)
	}
	userKey := vmessKey(u)
	var authID [16]byte
	if _, err := io.ReadFull(conn, authID[:]); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(kdf(userKey[:], kdfSaltAuthIDEncryption)[:16])
	var plainAuth [16]byte
	block.Decrypt(plainAuth[:], authID[:])
	if crc32.ChecksumIEEE(plainAuth[:12]) != binary.BigEndian.Uint32(plainAuth[12:]) {
		t.Fatal("bad AuthID checksum")
	}
	var encLen [2 + vmessChunkOverhead]byte
	if _, err := io.ReadFull(conn, encLen[:]); err != nil {
		t.Fatal(err)
	}
	var connNonce [8]byte
	if _, err := io.ReadFull(conn, connNonce[:]); err != nil {
		t.Fatal(err)
	}
	lenKey := kdf(userKey[:], kdfSaltHeaderLenKey, authID[:], connNonce[:])[:16]
	lenNonce := kdf(userKey[:], kdfSaltHeaderLenIV, authID[:], connNonce[:])[:12]
	plainLen, err := newAESGCM(lenKey).Open(nil, lenNonce, encLen[:], authID[:])
	if err != nil {
		t.Fatal(err)
	}
	headerLen := int(binary.BigEndian.Uint16(plainLen))
	encHeader := make([]byte, headerLen+vmessChunkOverhead)
	if _, err := io.ReadFull(conn, encHeader); err != nil {
		t.Fatal(err)
	}
	headerKey := kdf(userKey[:], kdfSaltHeaderKey, authID[:], connNonce[:])[:16]
	headerNonce := kdf(userKey[:], kdfSaltHeaderIV, authID[:], connNonce[:])[:12]
	header, err := newAESGCM(headerKey).Open(nil, headerNonce, encHeader, authID[:])
	if err != nil {
		t.Fatal(err)
	}
	if header[0] != 1 {
		t.Fatalf("bad version %d", header[0])
	}
	var nonce, key [16]byte
	copy(nonce[:], header[1:17])
	copy(key[:], header[17:33])
	respHeader := header[33]
	option := header[34]
	psec := header[35]
	command := header[37]
	return key, nonce, respHeader, option, psec & 0x0f, command
}

// readAEADFrame reads one masked-and-encrypted AEAD chunk and returns its
// plaintext, using the request body key/IV from the handshake.
func readAEADFrame(t *testing.T, r io.Reader, key, nonce [16]byte, security byte) []byte {
	t.Helper()
	mask := newSHAKEReaderForTest(nonce[:])
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	var mb [2]byte
	io.ReadFull(mask, mb[:])
	length := int(binary.BigEndian.Uint16(lenBuf[:]) ^ binary.BigEndian.Uint16(mb[:]))
	if length < vmessChunkOverhead {
		t.Fatalf("short AEAD chunk %d", length)
	}
	ct := make([]byte, length)
	if _, err := io.ReadFull(r, ct); err != nil {
		t.Fatal(err)
	}
	aead := newStreamAEAD(security, key[:], nonce[:])
	n := make([]byte, aead.NonceSize())
	copy(n, nonce[:])
	n[0], n[1] = 0, 0 // VMess overwrites the first two nonce bytes with the chunk counter
	pt, err := aead.Open(nil, n, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func newSHAKEReaderForTest(seed []byte) io.Reader {
	// Implemented locally to keep the test independent of helper visibility.
	return &shakeReader{data: shakeBytesForTest(seed, 4096)}
}

type shakeReader struct {
	data []byte
	off  int
}

func (r *shakeReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func shakeBytesForTest(seed []byte, n int) []byte {
	h := sha3.NewSHAKE128()
	_, _ = h.Write(seed)
	out := make([]byte, n)
	_, _ = io.ReadFull(h, out)
	return out
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCFB128MatchesStdlib(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	io.ReadFull(rand.Reader, key)
	io.ReadFull(rand.Reader, iv)
	src := make([]byte, 517)
	io.ReadFull(rand.Reader, src)

	block, _ := aes.NewCipher(key)
	want := make([]byte, len(src))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(want, src)

	got := make([]byte, len(src))
	stream, err := newCFBEncrypter128(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	stream.XORKeyStream(got, src)
	if !bytes.Equal(got, want) {
		t.Fatal("CFB-128 encrypt does not match crypto/cipher.NewCFBEncrypter")
	}

	dec, _ := newCFBDecrypter128(key, iv)
	round := make([]byte, len(want))
	dec.XORKeyStream(round, want)
	if !bytes.Equal(round, src) {
		t.Fatal("CFB-128 decrypt round trip failed")
	}
}

func TestVMessLegacyRoundTrip(t *testing.T) {
	client, err := NewVMessClientWithAlterId(testUUID, "aes-128-cfb", 4)
	if err != nil {
		t.Fatal(err)
	}
	cc, ss := net.Pipe()
	defer cc.Close()
	defer ss.Close()

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		key, nonce, respHeader, security, option, command := readLegacyRequest(t, ss, testUUID, 4)
		if security != vmessSecurityLegacy || command != vmessCmdTCP || option&vmessOptChunkStream == 0 {
			errCh <- fmt.Errorf("bad header: sec=%d opt=%d cmd=%d", security, option, command)
			return
		}

		// Server writes a 4-byte response header through the CFB stream and
		// continues the same stream for payload frames.
		respKey, respIV := vmessResponseLegacyKeys(key, nonce)
		respEnc, err := newCFBEncrypter128(respKey[:], respIV[:])
		if err != nil {
			errCh <- err
			return
		}
		resp := []byte{respHeader, option, 0, 0}
		respEnc.XORKeyStream(resp, resp)

		// Read the client's data frame.
		clientReader, err := newCFBReader(ss, key[:], nonce[:])
		if err != nil {
			errCh <- err
			return
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(clientReader, lenBuf[:]); err != nil {
			errCh <- err
			return
		}
		length := int(binary.BigEndian.Uint16(lenBuf[:]))
		frame := make([]byte, length)
		if _, err := io.ReadFull(clientReader, frame); err != nil {
			errCh <- err
			return
		}
		h := fnv.New32a()
		h.Write(frame[4:])
		if h.Sum32() != binary.BigEndian.Uint32(frame[:4]) {
			errCh <- fmt.Errorf("bad client frame checksum")
			return
		}
		if string(frame[4:]) != "hello-legacy" {
			errCh <- fmt.Errorf("unexpected client payload %q", frame[4:])
			return
		}

		// Now that the client's write has been consumed, send the 4-byte
		// response header followed by a payload frame on the same CFB stream.
		if _, err := ss.Write(resp); err != nil {
			errCh <- err
			return
		}

		// Send a payload frame back to the client.
		payload := []byte("world-legacy")
		out := make([]byte, 6+len(payload))
		binary.BigEndian.PutUint16(out[:2], uint16(4+len(payload)))
		h2 := fnv.New32a()
		h2.Write(payload)
		binary.BigEndian.PutUint32(out[2:6], h2.Sum32())
		copy(out[6:], payload)
		respEnc.XORKeyStream(out, out)
		if _, err := ss.Write(out); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	conn, err := client.DialConn(cc, "1.2.3.4", 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello-legacy")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world-legacy" {
		t.Fatalf("unexpected response payload %q", buf[:n])
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestVMessUDPPacketFormat(t *testing.T) {
	client, err := NewVMessClient(testUUID, "aes-128-gcm")
	if err != nil {
		t.Fatal(err)
	}
	cc, ss := net.Pipe()
	defer cc.Close()
	defer ss.Close()

	go func() {
		key, nonce, respHeader, option, security, command := readAEADHandshake(t, ss, testUUID)
		if command != vmessCmdUDP {
			t.Errorf("command = %d, want UDP(2)", command)
		}
		if security != vmessSecurityGCM {
			t.Errorf("security = %d", security)
		}
		if option&vmessOptChunkStream == 0 || option&vmessOptChunkMasking == 0 {
			t.Errorf("option = %d", option)
		}
		frame := readAEADFrame(t, ss, key, nonce, security)
		if string(frame) != "udp-payload" {
			t.Errorf("unexpected UDP payload %q", frame)
		}
		// Reply with one AEAD frame, encrypted with the RESPONSE keys.
		rk := sha256Sum(key[:])[:16]
		rn := sha256Sum(nonce[:])[:16]
		aead := newStreamAEAD(security, rk, rn)
		n := make([]byte, aead.NonceSize())
		copy(n, rn)
		n[0], n[1] = 0, 0
		pt := []byte("udp-reply")
		ct := aead.Seal(nil, n, pt, nil)
		respHdr := []byte{respHeader, option, 0, 0}
		lkey := kdf(rk, kdfSaltRespLenKey)[:16]
		liv := kdf(rn, kdfSaltRespLenIV)[:12]
		hkey := kdf(rk, kdfSaltRespHeaderKey)[:16]
		hiv := kdf(rn, kdfSaltRespHeaderIV)[:12]
		var encLen [2 + vmessChunkOverhead]byte
		binary.BigEndian.PutUint16(encLen[:2], uint16(len(respHdr)))
		newAESGCM(lkey).Seal(encLen[:0], liv, encLen[:2], nil)
		encHdr := newAESGCM(hkey).Seal(nil, hiv, respHdr, nil)
		maskOut := shakeBytesForTest(rn, 2)
		var fb [2]byte
		binary.BigEndian.PutUint16(fb[:], uint16(len(ct))^binary.BigEndian.Uint16(maskOut))
		ss.Write(append(append(append(encLen[:], encHdr...), fb[:]...), ct...))
	}()

	pc, err := client.DialPacketConn(cc, "example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("udp-payload"), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "udp-reply" {
		t.Fatalf("unexpected reply %q", buf[:n])
	}
	if addr == nil || addr.String() == "" {
		t.Fatal("nil source address")
	}
}

func TestVMessChacha20RoundTrip(t *testing.T) {
	client, err := NewVMessClient(testUUID, "chacha20-poly1305")
	if err != nil {
		t.Fatal(err)
	}
	cc, ss := net.Pipe()
	defer cc.Close()
	defer ss.Close()

	go func() {
		key, nonce, respHeader, option, security, command := readAEADHandshake(t, ss, testUUID)
		if command != vmessCmdTCP || security != vmessSecurityChacha {
			t.Errorf("command=%d security=%d", command, security)
		}
		frame := readAEADFrame(t, ss, key, nonce, security)
		if string(frame) != "chacha-payload" {
			t.Errorf("unexpected payload %q", frame)
		}
		// Build a chacha response frame.
		rk := sha256Sum(key[:])[:16]
		rn := sha256Sum(nonce[:])[:16]
		aead := newStreamAEAD(security, rk, rn)
		n := make([]byte, aead.NonceSize())
		copy(n, rn)
		n[0], n[1] = 0, 0
		ct := aead.Seal(nil, n, []byte("chacha-reply"), nil)
		lkey := kdf(rk, kdfSaltRespLenKey)[:16]
		liv := kdf(rn, kdfSaltRespLenIV)[:12]
		hkey := kdf(rk, kdfSaltRespHeaderKey)[:16]
		hiv := kdf(rn, kdfSaltRespHeaderIV)[:12]
		hdr := []byte{respHeader, option, 0, 0}
		var encLen [2 + vmessChunkOverhead]byte
		binary.BigEndian.PutUint16(encLen[:2], uint16(len(hdr)))
		newAESGCM(lkey).Seal(encLen[:0], liv, encLen[:2], nil)
		encHdr := newAESGCM(hkey).Seal(nil, hiv, hdr, nil)
		maskBytes := shakeBytesForTest(rn, 2)
		var fb [2]byte
		binary.BigEndian.PutUint16(fb[:], uint16(len(ct))^binary.BigEndian.Uint16(maskBytes))
		out := append(encLen[:], encHdr...)
		out = append(out, fb[:]...)
		out = append(out, ct...)
		ss.Write(out)
	}()

	conn, err := client.DialConn(cc, "1.2.3.4", 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("chacha-payload")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "chacha-reply" {
		t.Fatalf("unexpected reply %q", buf[:n])
	}
}
