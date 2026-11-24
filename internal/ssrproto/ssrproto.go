// Package ssrproto 是纯标准库实现的 ShadowsocksR (SSR) 出站客户端框架。
//
// 分层顺序与 shadowsocksr 一致：明文 -> protocol -> SS 流加密 -> obfs -> TCP。
//
// 支持情况：
//   - 加密：aes-256-cfb / aes-192-cfb / aes-128-cfb / chacha20（手写 CFB-128 与
//     SS 变体 ChaCha20，零外部依赖，不使用 crypto/cipher.NewCFBEncrypter）。
//   - 协议插件：auth_sha1_v4 / auth_sha1_v4_compatible（完整 CRC32 + 时间戳头 +
//     HMAC-SHA1 封装与解封装）。其它协议名会被识别但按 origin 处理。
//   - 混淆：tls1.2_ticket_auth（TLS ClientHello 前缀 + application-data 记录），
//     提供的是客户端框架；不校验服务端 auth 响应，与严格服务端互通性有限。
//
// 该包可与 internal/ssproto（SS AEAD）并存，互不依赖。
package ssrproto

import (
	"net"
	"sync"
)

// Config 描述一个 SSR 节点。
type Config struct {
	Method        string // aes-256-cfb / aes-128-cfb / chacha20 ...
	Password      string
	Protocol      string // origin / auth_sha1_v4 / auth_sha1_v4_compatible
	ProtocolParam string
	Obfs          string // plain / tls1.2_ticket_auth
	ObfsParam     string
}

// Conn 是在原始 TCP 连接之上完成 SSR 封装的 net.Conn。
type Conn struct {
	net.Conn

	method string
	key    []byte
	ivLen  int

	writeIV     []byte
	writeCipher streamCipher
	writeOnce   bool

	readCipher streamCipher

	proto *authState
	obfs  *tlsObfs

	addrHeader []byte

	muR     sync.Mutex
	encBuf  []byte // obfs 解帧后、尚未解密的密文
	outBuf  []byte // 解密并解协议后、等待 Read 的明文
	readErr error

	muW sync.Mutex
}

// Dial 在已建立 TCP 连接的 raw 上完成 SSR 握手，返回加密流。
// 对 tls1.2_ticket_auth，握手第一步（ClientHello）会在此立即写出。
func Dial(raw net.Conn, cfg Config, host string, port uint16) (net.Conn, error) {
	spec, err := lookupMethod(cfg.Method)
	if err != nil {
		return nil, err
	}
	key := evpBytesToKey([]byte(cfg.Password), spec.keyLen)
	writeIV, err := randBytes(spec.ivLen)
	if err != nil {
		return nil, err
	}
	wc, err := newStreamCipher(cfg.Method, key, writeIV, false)
	if err != nil {
		return nil, err
	}
	c := &Conn{
		Conn:        raw,
		method:      cfg.Method,
		key:         key,
		ivLen:       spec.ivLen,
		writeIV:     writeIV,
		writeCipher: wc,
		proto:       newAuthState(cfg.Protocol, cfg.Password, cfg.ProtocolParam),
		obfs:        newTLSObfs(cfg.Obfs, cfg.ObfsParam, key),
		addrHeader:  encodeAddr(host, port),
	}
	if hello := c.obfs.clientHello(); len(hello) > 0 {
		if _, err := raw.Write(hello); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Write 把明文按 protocol -> 流加密 -> obfs 顺序封装后写出。
func (c *Conn) Write(b []byte) (int, error) {
	c.muW.Lock()
	defer c.muW.Unlock()
	plain := c.proto.preEncrypt(b, c.addrHeader, c.key, c.writeIV)
	if len(plain) == 0 {
		return 0, nil
	}
	ct := make([]byte, len(plain))
	c.writeCipher.XORKeyStream(ct, plain)
	if !c.writeOnce {
		ct = append(append([]byte(nil), c.writeIV...), ct...)
		c.writeOnce = true
	}
	out := c.obfs.encode(ct)
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read 从网络读取并逆向 obfs -> 流解密 -> protocol 解封装。
func (c *Conn) Read(b []byte) (int, error) {
	c.muR.Lock()
	defer c.muR.Unlock()
	for len(c.outBuf) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if err := c.fill(); err != nil {
			c.readErr = err
			if len(c.outBuf) == 0 {
				return 0, err
			}
		}
	}
	n := copy(b, c.outBuf)
	c.outBuf = c.outBuf[n:]
	return n, nil
}

func (c *Conn) fill() error {
	buf := make([]byte, 8192)
	n, err := c.Conn.Read(buf)
	if n > 0 {
		decoded := c.obfs.decode(buf[:n])
		c.encBuf = append(c.encBuf, decoded...)
	}
	// 流加密在数据流开头带 IV；首次读取时提取并初始化读方向 cipher。
	if c.readCipher == nil && len(c.encBuf) >= c.ivLen {
		iv := append([]byte(nil), c.encBuf[:c.ivLen]...)
		c.encBuf = c.encBuf[c.ivLen:]
		rc, e := newStreamCipher(c.method, c.key, iv, true)
		if e != nil {
			return e
		}
		c.readCipher = rc
	}
	if c.readCipher != nil && len(c.encBuf) > 0 {
		pt := make([]byte, len(c.encBuf))
		c.readCipher.XORKeyStream(pt, c.encBuf)
		c.encBuf = nil
		out := c.proto.postDecrypt(pt)
		c.outBuf = append(c.outBuf, out...)
	}
	return err
}
