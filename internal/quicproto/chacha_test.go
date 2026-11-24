package quicproto

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"hash"
	"testing"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 8439 §2.3.2: ChaCha20 block function.
func TestChaCha20BlockVector(t *testing.T) {
	c, err := newChaCha20(hx(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	if err != nil {
		t.Fatal(err)
	}
	nonce := hx(t, "000000090000004a00000000")
	got := c.block(1, nonce)
	want := hx(t, "10f1e7e4d13b5915500fdd1fa32071c4"+
		"c7d1f4c733c068030422aa9ac3d46c4e"+
		"d2826446079faa0914c2d705d98b02a2"+
		"b5129cd1de164eb9cbd083e8a2503c4e")
	if !bytes.Equal(got[:], want) {
		t.Fatalf("block mismatch\ngot  %x\nwant %x", got, want)
	}
}

// RFC 8439 §2.4.2: ChaCha20 stream cipher ("Sunscreen").
func TestChaCha20StreamVector(t *testing.T) {
	c, err := newChaCha20(hx(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	got := make([]byte, len(plain))
	c.xorKeyStream(got, plain, hx(t, "000000000000004a00000000"))
	want := hx(t, "6e2e359a2568f98041ba0728dd0d6981"+
		"e97e7aec1d4360c20a27afccfd9fae0b"+
		"f91b65c5524733ab8f593dabcd62b357"+
		"1639d624e65152ab8f530c359f0861d8"+
		"07ca0dbf500d6a6156a38e088a22b65e"+
		"52bc514d16ccf806818ce91ab7793736"+
		"5af90bbf74a35be6b40b8eedf2785e42"+
		"874d")
	if !bytes.Equal(got, want) {
		t.Fatalf("stream mismatch\ngot  %x\nwant %x", got, want)
	}
}

// RFC 8439 §2.5.2: Poly1305 MAC.
func TestPoly1305Vector(t *testing.T) {
	key := hx(t, "85d6be7857556d337f4452fe42d506a8"+
		"0103808afb0db2fd4abff6af4149f51b")
	msg := []byte("Cryptographic Forum Research Group")
	got := make([]byte, 16)
	poly1305(got, msg, key)
	want := hx(t, "a8061dc1305136c6c22b8baf0c0127a9")
	if !bytes.Equal(got, want) {
		t.Fatalf("poly1305 mismatch\ngot  %x\nwant %x", got, want)
	}
}

// RFC 8439 §2.6.2: Poly1305 one-time key generation.
func TestPoly1305KeyGenVector(t *testing.T) {
	c, err := newChaCha20(hx(t, "808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f"))
	if err != nil {
		t.Fatal(err)
	}
	got := c.block(0, hx(t, "000000000001020304050607"))
	want := hx(t, "8ad5a08b905f81cc815040274ab29471"+
		"a833b637e3fd0da508dbb8e2fdd1a646")
	if !bytes.Equal(got[:32], want) {
		t.Fatalf("otk mismatch\ngot  %x\nwant %x", got[:32], want)
	}
}

// RFC 8439 §2.8.2: AEAD_CHACHA20_POLY1305.
func TestChaCha20Poly1305AEADVector(t *testing.T) {
	key := hx(t, "808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f")
	aead, err := newChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 8439 uses a 32-bit fixed-common part (7) + 64-bit IV.
	nonce := hx(t, "070000004041424344454647")
	aad := hx(t, "50515253c0c1c2c3c4c5c6c7")
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantCT := hx(t, "d31a8d34648e60db7b86afbc53ef7ec2"+
		"a4aded51296e08fea9e2b5a736ee62d6"+
		"3dbea45e8ca9671282fafb69da92728b"+
		"1a71de0a9e060b2905d6a5b67ecd3b36"+
		"92ddbd7f2d778b8c9803aee328091b58"+
		"fab324e4fad675945585808b4831d7bc"+
		"3ff4def08e4b7a9de576d26586cec64b"+
		"6116")
	wantTag := hx(t, "1ae10b594f09e26a7e902ecbd0600691")

	sealed := aead.Seal(nil, nonce, plain, aad)
	if !bytes.Equal(sealed[:len(plain)], wantCT) {
		for i := range wantCT {
			if sealed[i] != wantCT[i] {
				t.Fatalf("ciphertext mismatch at byte %d: got %02x want %02x\ngot  %x\nwant %x", i, sealed[i], wantCT[i], sealed[:len(plain)], wantCT)
			}
		}
		t.Fatalf("ciphertext length mismatch: got %d want %d", len(sealed), len(wantCT)+16)
	}
	if !bytes.Equal(sealed[len(plain):], wantTag) {
		t.Fatalf("tag mismatch\ngot  %x\nwant %x", sealed[len(plain):], wantTag)
	}
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("round trip failed")
	}
	// Tampering must be detected.
	sealed[len(plain)/2] ^= 0xff
	if _, err := aead.Open(nil, nonce, sealed, aad); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

// RFC 9001 Appendix A.5: full ChaCha20-Poly1305 short-header packet, including
// key derivation, AEAD, and the ChaCha20 header-protection mask.
func TestQUICChaCha20ShortHeaderVector(t *testing.T) {
	secret := hx(t, "9ac312a7f877468ebe69422748ad00a1"+
		"5443f18203a07d6060f688f30f21632b")
	var h func() hash.Hash = sha256.New
	if got := hex.EncodeToString(expandLabelWithHash(h, secret, "quic key", nil, 32)); got !=
		"c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8" {
		t.Fatalf("quic key = %s", got)
	}
	if got := hex.EncodeToString(expandLabelWithHash(h, secret, "quic iv", nil, 12)); got != "e0459b3474bdd0e44a41c144" {
		t.Fatalf("quic iv = %s", got)
	}
	if got := hex.EncodeToString(expandLabelWithHash(h, secret, "quic hp", nil, 32)); got !=
		"25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4" {
		t.Fatalf("quic hp = %s", got)
	}
	if got := hex.EncodeToString(expandLabelWithHash(h, secret, "quic ku", nil, 32)); got !=
		"1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9" {
		t.Fatalf("quic ku = %s", got)
	}

	pp, err := newPacketProtection(secret, tls.TLS_CHACHA20_POLY1305_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !pp.hpChaCha || len(pp.hpKey) != 32 || pp.hp != nil {
		t.Fatalf("bad ChaCha packet protection setup: %+v", pp)
	}

	// Unprotected short header (empty DCID, 3-byte PN) + PING payload.
	header := hx(t, "4200bff4")
	payload := []byte{0x01}
	got, err := pp.seal(header, 1, 3, payload, 654360564)
	if err != nil {
		t.Fatal(err)
	}
	want := hx(t, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
	if !bytes.Equal(got, want) {
		t.Fatalf("protected packet mismatch\ngot  %x\nwant %x", got, want)
	}

	// The RFC's sample starts 4 bytes after the PN field.
	sample := hx(t, "5e5cd55c41f69080575d7999c25a5bfb")
	mask, err := chacha20HPMask(pp.hpKey, sample)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mask[:]); got != "aefefe7d03" {
		t.Fatalf("header protection mask = %s, want aefefe7d03", got)
	}

	// The 3-byte PN is decoded against the largest PN seen in this space.
	pn, _, h2, opened, err := pp.openFull(got, 1, false, 654360563)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if pn != 654360564 || !bytes.Equal(h2, header) || !bytes.Equal(opened, payload) {
		t.Fatalf("open round trip: pn=%d header=%x payload=%x", pn, h2, opened)
	}
}
