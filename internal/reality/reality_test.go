package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// TestDialAgainstStdlibTLS 用标准库 TLS 1.3 服务端验证手工握手和记录层。
func TestDialAgainstStdlibTLS(t *testing.T) {
	skipCertVerifyForTest = true
	defer func() { skipCertVerifyForTest = false }()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		conn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		})
		if err := conn.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n == 0 {
			conn.Close()
			return
		}
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"
		_, _ = conn.Write([]byte(resp))
		_ = conn.Close()
	}()

	dummy, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := Dial(context.Background(), raw, Config{
		ServerName: "example.com",
		PublicKey:  base64.RawURLEncoding.EncodeToString(dummy.PublicKey().Bytes()),
		ShortID:    "0011223344556677",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	n, err := io.WriteString(conn, req)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(req) {
		t.Fatalf("short write: %d/%d", n, len(req))
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "\r\n\r\nhi") {
		t.Fatalf("bad response: %q", data)
	}
}

// TestSessionIDAuth 校验 session id 的加密格式与服务端解密一致。
func TestSessionIDAuth(t *testing.T) {
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientShared, _ := client.ECDH(server.PublicKey())
	serverShared, _ := server.ECDH(client.PublicKey())
	var random [32]byte
	_, _ = rand.Read(random[:])
	ck := deriveAuthKey(clientShared, random[:])
	sk := deriveAuthKey(serverShared, random[:])
	if !bytes.Equal(ck, sk) {
		t.Fatal("auth key mismatch")
	}
	aad := []byte("client hello")
	blob, err := sealSessionID(ck, random[:], []byte{1, 2, 3, 4, 5, 6, 7, 8}, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 32 {
		t.Fatalf("session id length = %d", len(blob))
	}
	block, _ := aes.NewCipher(sk)
	aead, _ := cipher.NewGCM(block)
	plain, err := aead.Open(nil, random[20:32], blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if plain[0] != 1 || plain[1] != 8 || plain[2] != 2 || !bytes.Equal(plain[8:16], []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("bad session id plaintext: %x", plain)
	}
}

// TestHKDFVector 使用 RFC 5869 的 SHA-256 测试向量。
func TestHKDFVector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	prk := hkdfExtract(sha256.New, salt, ikm)
	got := hex.EncodeToString(hkdfExpand(prk, info, 42, sha256.New))
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got != want {
		t.Fatalf("hkdf got %s want %s", got, want)
	}
}
