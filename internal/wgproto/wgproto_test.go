package wgproto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBLAKE2sVectors(t *testing.T) {
	// BLAKE2s-256 (RFC 7693 / blake2.net KAT)
	unkeyed := []struct {
		in, want string
	}{
		{"", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
		{"616263", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"},
	}
	for _, v := range unkeyed {
		got := blake2sSum256(mustHex(t, v.in))
		if hex.EncodeToString(got[:]) != v.want {
			t.Errorf("blake2s256(%s) = %x, want %s", v.in, got, v.want)
		}
	}

	// 带密钥向量（blake2s-kat.txt, key = 00..1f），BLAKE2s-256
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyed256 := []struct {
		len  int
		want string
	}{
		{0, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"},
		{64, "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"},
	}
	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(i)
	}
	for _, v := range keyed256 {
		h, _ := newBLAKE2s(key, blake2sSize)
		_, _ = h.Write(input[:v.len])
		got := hex.EncodeToString(h.Sum(nil))
		if got != v.want {
			t.Errorf("keyed blake2s256(len=%d) = %s, want %s", v.len, got, v.want)
		}
	}

	// 带密钥 BLAKE2s-128（WireGuard Mac 的原语，16 字节输出）
	keyed128 := []struct {
		len  int
		want string
	}{
		{0, "9536f9b267655743dee97b8a670f9f53"},
		{1, "13bacfb85b48a1223c595f8c1e7e82cb"},
	}
	for _, v := range keyed128 {
		got := hex.EncodeToString(blake2sMAC(key, input[:v.len], blake2sSize128))
		if got != v.want {
			t.Errorf("blake2s128(len=%d) = %s, want %s", v.len, got, v.want)
		}
	}
}

func TestChaCha20BlockVector(t *testing.T) {
	// RFC 8439 §2.3.2
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := mustHex(t, "000000090000004a00000000")
	var k [32]byte
	copy(k[:], key)
	var out [64]byte
	chacha20Block(&k, 1, nonce, &out)
	want := "10f1e7e4d13b5915500fdd1fa32071c4" +
		"c7d1f4c733c068030422aa9ac3d46c4e" +
		"d2826446079faa0914c2d705d98b02a2" +
		"b5129cd1de164eb9cbd083e8a2503c4e"
	if hex.EncodeToString(out[:]) != want {
		t.Errorf("chacha20Block = %x, want %s", out, want)
	}
}

func TestPoly1305Vector(t *testing.T) {
	// RFC 8439 §2.5.2
	key := mustHex(t, "85d6be7857556d337f4452fe42d506a8"+
		"0103808afb0db2fd4abff6af4149f51b")
	msg := []byte("Cryptographic Forum Research Group")
	var k [32]byte
	copy(k[:], key)
	got := poly1305Tag(&k, msg)
	want := "a8061dc1305136c6c22b8baf0c0127a9"
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("poly1305Tag = %x, want %s", got, want)
	}
}

func TestAEADVector(t *testing.T) {
	// RFC 8439 §2.8.2
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "070000004041424344454647")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you " +
		"only one tip for the future, sunscreen would be it.")
	aead, err := newChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, nonce, plain, aad)
	wantCipher := "d31a8d34648e60db7b86afbc53ef7ec2" +
		"a4aded51296e08fea9e2b5a736ee62d6" +
		"3dbea45e8ca9671282fafb69da92728b" +
		"1a71de0a9e060b2905d6a5b67ecd3b36" +
		"92ddbd7f2d778b8c9803aee328091b58" +
		"fab324e4fad675945585808b4831d7bc" +
		"3ff4def08e4b7a9de576d26586cec64b" +
		"6116"
	wantTag := "1ae10b594f09e26a7e902ecbd0600691"
	if len(sealed) != len(plain)+16 {
		t.Fatalf("sealed length = %d", len(sealed))
	}
	if hex.EncodeToString(sealed[:len(plain)]) != wantCipher {
		t.Errorf("ciphertext = %x, want %s", sealed[:len(plain)], wantCipher)
	}
	if hex.EncodeToString(sealed[len(plain):]) != wantTag {
		t.Errorf("tag = %x, want %s", sealed[len(plain):], wantTag)
	}
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Errorf("Open mismatch")
	}
	// 篡改 AAD 必须失败
	badAAD := append([]byte(nil), aad...)
	badAAD[0] ^= 1
	if _, err := aead.Open(nil, nonce, sealed, badAAD); err == nil {
		t.Error("Open accepted tampered AAD")
	}
}

func TestX25519Vector(t *testing.T) {
	// RFC 7748 §6.1
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePubWant := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPubWant := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	sharedWant := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	curve := ecdh.X25519()
	a, err := curve.NewPrivateKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := curve.NewPrivateKey(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(a.PublicKey().Bytes()); got != alicePubWant {
		t.Errorf("alice pub = %s, want %s", got, alicePubWant)
	}
	if got := hex.EncodeToString(b.PublicKey().Bytes()); got != bobPubWant {
		t.Errorf("bob pub = %s, want %s", got, bobPubWant)
	}
	ss, err := a.ECDH(b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ss); got != sharedWant {
		t.Errorf("shared = %s, want %s", got, sharedWant)
	}
}

// responderHandshake 在测试中独立实现响应方推导（白皮书 §5.4.2/§5.4.3），
// 用于验证发起方消息与密钥派生是否与规范一致。
func responderHandshake(t *testing.T, initMsg []byte, respStatic *ecdh.PrivateKey, initiatorPub []byte) ([]byte, [32]byte, [32]byte) {
	t.Helper()
	curve := ecdh.X25519()
	initPub, err := curve.NewPublicKey(initiatorPub)
	if err != nil {
		t.Fatal(err)
	}
	ephemeralPub, err := curve.NewPublicKey(initMsg[8:40])
	if err != nil {
		t.Fatal(err)
	}

	ck := blake2sSum256(noiseConstruction)
	var h [32]byte
	h = ck
	mixHash(&h, noiseIdentifier)
	// 双方都混入响应方的静态公钥（pre-message <- s）
	mixHash(&h, respStatic.PublicKey().Bytes())
	mixHash(&h, initMsg[8:40])
	mixKey(&ck, initMsg[8:40])

	ss, err := respStatic.ECDH(ephemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	kdf2(&ck, &key, ck[:], ss)
	decodedStatic, err := aeadOpen(&key, initMsg[40:88], h[:])
	if err != nil {
		t.Fatalf("static decrypt: %v", err)
	}
	if !bytes.Equal(decodedStatic, initiatorPub) {
		t.Fatalf("responder decoded wrong static key")
	}
	mixHash(&h, initMsg[40:88])

	ss, err = respStatic.ECDH(initPub)
	if err != nil {
		t.Fatal(err)
	}
	kdf2(&ck, &key, ck[:], ss)
	if _, err := aeadOpen(&key, initMsg[88:116], h[:]); err != nil {
		t.Fatalf("timestamp decrypt: %v", err)
	}
	mixHash(&h, initMsg[88:116])

	// 生成响应方 ephemeral
	er, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	erPub := er.PublicKey().Bytes()
	mixHash(&h, erPub)
	mixKey(&ck, erPub)
	ss, err = er.ECDH(ephemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	mixKey(&ck, ss)
	ss, err = er.ECDH(initPub)
	if err != nil {
		t.Fatal(err)
	}
	mixKey(&ck, ss)

	var tau [32]byte
	kdf3(&ck, &tau, &key, ck[:], zeroPSK[:])
	mixHash(&h, tau[:])
	empty, err := aeadSeal(&key, nil, h[:])
	if err != nil {
		t.Fatal(err)
	}
	mixHash(&h, empty)

	resp := make([]byte, messageResponseSize)
	binary.LittleEndian.PutUint32(resp[0:4], messageResponseType)
	binary.LittleEndian.PutUint32(resp[4:8], 0x11223344)
	binary.LittleEndian.PutUint32(resp[8:12], binary.LittleEndian.Uint32(initMsg[4:8]))
	copy(resp[12:44], erPub)
	copy(resp[44:60], empty)

	// 响应方 KDF2(recv, send, C, nil)
	var recvKey, sendKey [32]byte
	kdf2(&recvKey, &sendKey, ck[:], nil)
	return resp, sendKey, recvKey
}

func TestHandshakeRoundTrip(t *testing.T) {
	curve := ecdh.X25519()
	initStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	respStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initPub := initStatic.PublicKey().Bytes()
	respPub := respStatic.PublicKey().Bytes()

	const index = 0x01020304
	hs, err := newNoiseHandshake(respPub, index)
	if err != nil {
		t.Fatal(err)
	}
	initMsg, err := hs.createInitiation(initStatic, respPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(initMsg) != messageInitiationSize {
		t.Fatalf("initiation size = %d", len(initMsg))
	}
	if binary.LittleEndian.Uint32(initMsg[0:4]) != 1 ||
		binary.LittleEndian.Uint32(initMsg[4:8]) != index {
		t.Fatal("bad initiation header")
	}

	// 校验 mac1
	var macKeyInput [40]byte
	copy(macKeyInput[:8], noiseLabelMAC1)
	copy(macKeyInput[8:], respPub)
	macKey := blake2sSum256(macKeyInput[:])
	wantMAC1 := blake2sMAC(macKey[:], initMsg[:116], blake2sSize128)
	if !bytes.Equal(initMsg[116:132], wantMAC1) {
		t.Error("mac1 mismatch")
	}

	respMsg, respSend, respRecv := responderHandshake(t, initMsg, respStatic, initPub)
	initSend, initRecv, err := hs.consumeResponse(respMsg, initStatic)
	if err != nil {
		t.Fatal(err)
	}
	if initSend != respRecv || initRecv != respSend {
		t.Error("transport keys do not match responder view")
	}

	// 发起方用 sendKey 发一个 transport data 包，响应方用 recvKey 解密
	aead, _ := newChaCha20Poly1305(initSend[:])
	nonce := makeNonce(42)
	payload := []byte("45 00 00 14 ... inner IP packet")
	sealed := aead.Seal(nil, nonce[:], payload, nil)

	respAEAD, _ := newChaCha20Poly1305(respRecv[:])
	got, err := respAEAD.Open(nil, nonce[:], sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("transport data mismatch")
	}
}
