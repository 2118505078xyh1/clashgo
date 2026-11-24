package ssrproto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// 手写 CFB-128 必须与标准库 cipher.NewCFBEncrypter 逐字节一致。
// 同时验证任意分块边界下流式语义正确。
func TestCFBMatchesStdlib(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("abcdef0123456789abcdef0123456789")
	pt := []byte("The quick brown fox jumps over the lazy dog. " +
		"SSR stream ciphers need a correct CFB-128 implementation. " +
		"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(pt))
	// SS 的 aes-256-cfb 发送 32 字节 IV，但 AES-CFB 只使用前 16 字节。
	cipher.NewCFBEncrypter(block, iv[:block.BlockSize()]).XORKeyStream(want, pt)

	got := make([]byte, len(pt))
	c := newCFBStream(block, iv, false)
	chunks := []int{1, 15, 16, 17, 3, 64, 7, 1, 31, 2, 13}
	for off, i := 0, 0; off < len(pt); i++ {
		n := chunks[i%len(chunks)]
		if off+n > len(pt) {
			n = len(pt) - off
		}
		c.XORKeyStream(got[off:off+n], pt[off:off+n])
		off += n
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("CFB mismatch\n got: %x\nwant: %x", got, want)
	}

	// 解密方向恢复明文。
	out := make([]byte, len(want))
	d := newCFBStream(block, iv, true)
	for off, i := 0, 0; off < len(want); i++ {
		n := chunks[i%len(chunks)]
		if off+n > len(want) {
			n = len(want) - off
		}
		d.XORKeyStream(out[off:off+n], want[off:off+n])
		off += n
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("CFB decrypt mismatch\n got: %x\nwant: %x", out, pt)
	}
}

// 三种 method 的加密往返。
func TestStreamRoundTrip(t *testing.T) {
	pt := bytes.Repeat([]byte("ssr-stream-roundtrip-"), 50)
	for _, method := range []string{"aes-256-cfb", "aes-128-cfb", "chacha20"} {
		t.Run(method, func(t *testing.T) {
			spec, err := lookupMethod(method)
			if err != nil {
				t.Fatal(err)
			}
			key := evpBytesToKey([]byte("password"), spec.keyLen)
			iv, err := randBytes(spec.ivLen)
			if err != nil {
				t.Fatal(err)
			}
			e, err := newStreamCipher(method, key, iv, false)
			if err != nil {
				t.Fatal(err)
			}
			d, err := newStreamCipher(method, key, iv, true)
			if err != nil {
				t.Fatal(err)
			}
			ct := make([]byte, len(pt))
			e.XORKeyStream(ct, pt)
			if bytes.Equal(ct, pt) {
				t.Fatal("ciphertext equals plaintext")
			}
			got := make([]byte, len(ct))
			d.XORKeyStream(got, ct)
			if !bytes.Equal(got, pt) {
				t.Fatal("round-trip mismatch")
			}
		})
	}
}

// auth_sha1_v4 数据块的 CRC32/adler32 封装可由 postDecrypt 正确还原。
func TestAuthSHA1V4DataFraming(t *testing.T) {
	a := newAuthState("auth_sha1_v4", "pw", "")
	payload := []byte("hello shadowsocksr auth_sha1_v4")
	framed := a.packData(payload)

	// 首 2 字节是长度，2:4 是该长度的 CRC32 低 16 位。
	if int(binary.BigEndian.Uint16(framed[0:2])) != len(framed) {
		t.Fatalf("bad length field: %d != %d", binary.BigEndian.Uint16(framed[0:2]), len(framed))
	}
	if binary.LittleEndian.Uint16(framed[2:4]) != uint16(calcCRC32(framed, 2)) {
		t.Fatal("bad CRC16 of length")
	}
	if !checkAdler32(framed, len(framed)) {
		t.Fatal("bad adler32")
	}
	got := a.postDecrypt(framed)
	if !bytes.Equal(got, payload) {
		t.Fatalf("postDecrypt mismatch: %q != %q", got, payload)
	}
}

// auth_sha1_v4 握手头包含时间戳、clientID、connectionID 与 HMAC。
func TestAuthSHA1V4Header(t *testing.T) {
	a := newAuthState("auth_sha1_v4", "pw", "")
	key := evpBytesToKey([]byte("pw"), 32)
	iv, _ := randBytes(32)
	addr := encodeAddr("example.com", 443)
	head := a.packAuthData(addr, key, iv)

	if len(head) < 12+obfsHMACSHA1Len {
		t.Fatal("auth header too short")
	}
	if int(binary.BigEndian.Uint16(head[0:2])) != len(head) {
		t.Fatal("bad auth header length")
	}
	randLen := int(head[6])
	if head[6] == 0xFF {
		randLen = int(binary.BigEndian.Uint16(head[7:9]))
	}
	dataOffset := randLen + 6
	ts := binary.LittleEndian.Uint32(head[dataOffset : dataOffset+4])
	if ts == 0 {
		t.Fatal("missing timestamp")
	}
	if !bytes.Equal(head[dataOffset+12:dataOffset+12+len(addr)], addr) {
		t.Fatal("address header not embedded")
	}
}

// TLS 混淆：ClientHello 记录头合法，encode/decode 往返正确。
func TestTLSObfsFraming(t *testing.T) {
	key := evpBytesToKey([]byte("pw"), 32)
	o := newTLSObfs("tls1.2_ticket_auth", "www.example.com,www.test.com", key)
	hello := o.clientHello()
	if len(hello) < 5 || hello[0] != 0x16 || hello[1] != 0x03 || hello[2] != 0x01 {
		t.Fatalf("bad ClientHello header: %x", hello[:min(5, len(hello))])
	}
	if int(binary.BigEndian.Uint16(hello[3:5])) != len(hello)-5 {
		t.Fatal("bad ClientHello record length")
	}
	if !bytes.Contains(hello, []byte("www.example.com")) {
		t.Fatal("missing SNI host")
	}

	payload := bytes.Repeat([]byte("tls-app-data-"), 200) // >1024，触发多记录分包
	encoded := o.encode(payload)
	sender := newTLSObfs("tls1.2_ticket_auth", "www.example.com", key)
	// sender 的 clientID 与 o 不同，但 decode 只做记录层拆帧，不校验 auth。
	decoded := sender.decode(encoded)
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("obfs round-trip mismatch: got %d bytes, want %d", len(decoded), len(payload))
	}
	// ClientHello 是 0x16 记录，应被 decode 跳过。
	if out := sender.decode(hello); len(out) != 0 {
		t.Fatalf("ClientHello should be skipped, got %d bytes", len(out))
	}
}

// 端到端：origin + plain，双向 net.Pipe 往返。
func TestDialRoundTripOrigin(t *testing.T) {
	for _, method := range []string{"aes-256-cfb", "chacha20"} {
		t.Run(method, func(t *testing.T) {
			cfg := Config{Method: method, Password: "pw", Protocol: "origin", Obfs: "plain"}
			clientRaw, serverRaw := net.Pipe()
			client, err := Dial(clientRaw, cfg, "example.com", 443)
			if err != nil {
				t.Fatal(err)
			}
			server := testServerConn(serverRaw, cfg)
			go func() {
				buf := make([]byte, 4096)
				n, _ := server.Read(buf)
				// origin 下服务端读到的是「地址头 + 业务数据」，需自行剥离地址头。
				addrLen := len(encodeAddr("example.com", 443))
				_, _ = server.Write(append([]byte("reply:"), buf[addrLen:n]...))
				server.Close()
			}()

			msg := []byte("hello shadowsocksr over net.Pipe")
			if _, err := client.Write(msg); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4096)
			n, err := io.ReadFull(client, buf[:len(msg)+6])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:len(msg)+6], append([]byte("reply:"), msg...)) {
				t.Fatalf("bad reply: %q", buf[:n])
			}
			client.Close()
		})
	}
}

// 端到端：auth_sha1_v4 + tls1.2_ticket_auth，验证客户端完整写路径。
func TestDialRoundTripAuthTLS(t *testing.T) {
	cfg := Config{
		Method: "aes-256-cfb", Password: "pw",
		Protocol: "auth_sha1_v4", Obfs: "tls1.2_ticket_auth",
		ObfsParam: "www.example.com",
	}
	clientRaw, serverRaw := net.Pipe()
	done := make(chan []byte, 1)
	go func() {
		spec, _ := lookupMethod(cfg.Method)
		key := evpBytesToKey([]byte(cfg.Password), spec.keyLen)
		obfs := newTLSObfs(cfg.Obfs, cfg.ObfsParam, key)
		buf := make([]byte, 8192)

		// 第一包：ClientHello（被 decode 跳过）。
		n, _ := serverRaw.Read(buf)
		_ = obfs.decode(buf[:n])
		// 第二包：handshake finish + application data。
		n, _ = serverRaw.Read(buf)
		decoded := obfs.decode(buf[:n])

		iv := decoded[:spec.ivLen]
		dc, _ := newStreamCipher(cfg.Method, key, iv, true)
		pt := make([]byte, len(decoded)-spec.ivLen)
		dc.XORKeyStream(pt, decoded[spec.ivLen:])

		// auth 握手头内嵌了地址前缀，数据块里是剩余部分。
		hlen := int(binary.BigEndian.Uint16(pt[:2]))
		randLen := int(pt[6])
		if pt[6] == 0xFF {
			randLen = int(binary.BigEndian.Uint16(pt[7:9]))
		}
		dataOffset := randLen + 6
		embeddedLen := hlen - dataOffset - 12 - obfsHMACSHA1Len
		prefix := append([]byte(nil), pt[dataOffset+12:dataOffset+12+embeddedLen]...)

		a := newAuthState(cfg.Protocol, cfg.Password, cfg.ProtocolParam)
		plain := append(prefix, a.postDecrypt(pt[hlen:])...)
		done <- plain
		serverRaw.Close()
	}()

	client, err := Dial(clientRaw, cfg, "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("payload-after-auth-and-tls")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	plain := <-done
	want := append(encodeAddr("example.com", 443), msg...)
	if !bytes.Equal(plain, want) {
		t.Fatalf("server got %q, want %q", plain, want)
	}
	client.Close()
}

// 测试内使用的“服务端”Conn：不发地址头（sentHeader=true）。
func testServerConn(raw net.Conn, cfg Config) *Conn {
	spec, _ := lookupMethod(cfg.Method)
	key := evpBytesToKey([]byte(cfg.Password), spec.keyLen)
	iv, _ := randBytes(spec.ivLen)
	wc, _ := newStreamCipher(cfg.Method, key, iv, false)
	p := newAuthState(cfg.Protocol, cfg.Password, cfg.ProtocolParam)
	p.sentHeader = true
	return &Conn{
		Conn: raw, method: cfg.Method, key: key, ivLen: spec.ivLen,
		writeIV: iv, writeCipher: wc, proto: p,
		obfs: newTLSObfs(cfg.Obfs, cfg.ObfsParam, key),
	}
}

// 使用 Go 1.21+ 内建 min。
