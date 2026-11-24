package ssproto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

const sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

// RFC 8439 第 2.3.2 节 ChaCha20 block function。
func TestChaCha20BlockVector(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := mustHex(t, "000000090000004a00000000")
	want := mustHex(t, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
	got := chacha20Block(key, 1, nonce)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("chacha20Block mismatch\n got: %x\nwant: %x", got, want)
	}
}

// XChaCha draft A.2.1 HChaCha20 test vector。
func TestHChaCha20Vector(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := mustHex(t, "000000090000004a0000000031415927")
	want := mustHex(t, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
	got := hChaCha20(key, nonce)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("hChaCha20 mismatch\n got: %x\nwant: %x", got, want)
	}
}

// RFC 8439 第 2.5.2 节 Poly1305。
func TestPoly1305Vector(t *testing.T) {
	key := mustHex(t, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	want := mustHex(t, "a8061dc1305136c6c22b8baf0c0127a9")
	got := newPoly1305(key).mac([]byte("Cryptographic Forum Research Group"))
	if !bytes.Equal(got[:], want) {
		t.Fatalf("poly1305 mismatch\n got: %x\nwant: %x", got, want)
	}
}

// RFC 8439 第 2.8.2 节 AEAD_CHACHA20_POLY1305 与 XChaCha draft A.3.1。
func TestAEADKnownVectors(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := []byte(sunscreen)

	tests := []struct {
		name, nonce, ct, tag string
		newAEAD              func([]byte) (cipher.AEAD, error)
	}{
		{
			name:    "chacha20-ietf-poly1305",
			nonce:   "070000004041424344454647",
			ct:      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
			tag:     "1ae10b594f09e26a7e902ecbd0600691",
			newAEAD: newChaCha20IETFPoly1305,
		},
		{
			name:    "xchacha20-ietf-poly1305",
			nonce:   "404142434445464748494a4b4c4d4e4f5051525354555657",
			ct:      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
			tag:     "c0875924c1c7987947deafd8780acf49",
			newAEAD: newXChaCha20IETFPoly1305,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aead, err := tt.newAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			nonce := mustHex(t, tt.nonce)
			wantCT := mustHex(t, tt.ct)
			wantTag := mustHex(t, tt.tag)

			got := aead.Seal(nil, nonce, pt, aad)
			if !bytes.Equal(got[:len(pt)], wantCT) {
				t.Fatalf("Seal ciphertext mismatch\n got: %x\nwant: %x", got[:len(pt)], wantCT)
			}
			if !bytes.Equal(got[len(pt):], wantTag) {
				t.Fatalf("Seal tag mismatch\n got: %x\nwant: %x", got[len(pt):], wantTag)
			}
			dec, err := aead.Open(nil, nonce, append(append([]byte{}, wantCT...), wantTag...), aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(dec, pt) {
				t.Fatalf("Open mismatch: %q", dec)
			}
		})
	}
}

// 各方法 Seal/Open 往返（含 AAD 与篡改检测）。
func TestAEADRoundTrip(t *testing.T) {
	methods := []string{"aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	for _, name := range methods {
		t.Run(name, func(t *testing.T) {
			m, err := NewMethod(name, "password")
			if err != nil {
				t.Fatal(err)
			}
			aead, err := m.subkey(mustHex(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			pt := []byte("hello shadowsocks udp+tcp")
			aad := []byte("aad-123")

			ct := aead.Seal(nil, nonce, pt, aad)
			got, err := aead.Open(nil, nonce, ct, aad)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("roundtrip failed: %q, %v", got, err)
			}
			bad := append([]byte{}, ct...)
			bad[0] ^= 1
			if _, err := aead.Open(nil, nonce, bad, aad); err == nil {
				t.Fatal("tampered ciphertext accepted")
			}
		})
	}
}

// 端到端 UDP 包格式验证：模拟 SS 服务端接收/回包。
func TestUDPPacketRoundTrip(t *testing.T) {
	for _, name := range []string{"aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		t.Run(name, func(t *testing.T) {
			server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			m, err := NewMethod(name, "pass")
			if err != nil {
				t.Fatal(err)
			}
			pc, err := m.ListenPacket(client)
			if err != nil {
				t.Fatal(err)
			}

			payload := []byte("udp-payload-12345")
			target := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
			n, err := pc.WriteTo(payload, target)
			if err != nil || n != len(payload) {
				t.Fatalf("WriteTo: %d, %v", n, err)
			}

			// 服务端：解包并校验地址与载荷。
			sbuf := make([]byte, 65535)
			sn, _, err := server.ReadFromUDP(sbuf)
			if err != nil {
				t.Fatal(err)
			}
			salt := sbuf[:m.keyLen]
			aead, err := m.subkey(salt)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, aead.NonceSize())
			lenPT, err := aead.Open(nil, nonce, sbuf[m.keyLen:m.keyLen+2+16], nil)
			if err != nil {
				t.Fatal(err)
			}
			incNonce(nonce)
			l := int(lenPT[0])<<8 | int(lenPT[1])
			inner, err := aead.Open(nil, nonce, sbuf[m.keyLen+2+16:m.keyLen+2+16+l+16], nil)
			if err != nil {
				t.Fatal(err)
			}
			host, port, off, err := parseSocksAddr(inner)
			if err != nil {
				t.Fatal(err)
			}
			if host != "8.8.8.8" || port != 53 || !bytes.Equal(inner[off:], payload) {
				t.Fatalf("bad inner packet: host=%s port=%d payload=%q", host, port, inner[off:])
			}

			// 服务端回包：源地址为 example.com:443。
			respSalt := make([]byte, m.keyLen)
			if _, err := rand.Read(respSalt); err != nil {
				t.Fatal(err)
			}
			respAEAD, err := m.subkey(respSalt)
			if err != nil {
				t.Fatal(err)
			}
			addrBytes := encodeAddr("example.com", 443)
			respPT := append(append([]byte{}, addrBytes...), []byte("response-payload")...)
			var lb [2]byte
			lb[0], lb[1] = byte(len(respPT)>>8), byte(len(respPT))
			respNonce := make([]byte, respAEAD.NonceSize())
			resp := append([]byte{}, respSalt...)
			resp = append(resp, respAEAD.Seal(nil, respNonce, lb[:], nil)...)
			incNonce(respNonce)
			resp = append(resp, respAEAD.Seal(nil, respNonce, respPT, nil)...)
			if _, err := server.WriteToUDP(resp, client.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}

			// 客户端：解密回包并校验源地址。
			rbuf := make([]byte, 1500)
			rn, raddr, err := pc.ReadFrom(rbuf)
			if err != nil {
				t.Fatal(err)
			}
			if string(rbuf[:rn]) != "response-payload" {
				t.Fatalf("bad response: %q", rbuf[:rn])
			}
			if raddr.String() != "example.com:443" {
				t.Fatalf("bad source addr: %s", raddr)
			}
			_ = sn
		})
	}
}
