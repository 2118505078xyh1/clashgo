package ssrproto

// 本文件实现 tls1.2_ticket_auth 混淆的客户端框架：
//  1. 发送模拟 TLS 1.2 ClientHello 的记录作为握手首包；
//  2. 发送客户端 auth 记录（ChangeCipherSpec + handshake + HMAC）；
//  3. 之后所有密文包成 TLS application-data 记录（0x17 0x03 0x03 len16 data）。
//
// 兼容性限制：真实 SSR 的 tls1.2_ticket_auth 是双向握手，客户端在发送完
// ClientHello 后应校验服务端返回的 auth 记录再进入数据阶段。本实现不校验
// 服务端 auth（仅按长度跳过），因此与部分严格服务端互通性有限，见包注释。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

type tlsObfs struct {
	tls      bool
	host     string
	key      []byte
	clientID [32]byte

	finishSent bool
	decodeMu   sync.Mutex
	rbuf       []byte
}

func newTLSObfs(obfs, param string, key []byte) *tlsObfs {
	name := strings.ToLower(strings.TrimSpace(obfs))
	t := &tlsObfs{
		tls:  name == "tls1.2_ticket_auth" || name == "tls1.2_ticket_fastauth",
		key:  append([]byte(nil), key...),
		host: strings.TrimSpace(strings.Split(param, ",")[0]),
	}
	_, _ = rand.Read(t.clientID[:])
	return t
}

// hmacSHA1 是 SSR 混淆层使用的 HMAC-SHA1(key || clientID, data)[:10]。
func (t *tlsObfs) hmacSHA1(data []byte) []byte {
	hkey := make([]byte, 0, len(t.key)+len(t.clientID))
	hkey = append(hkey, t.key...)
	hkey = append(hkey, t.clientID[:]...)
	mac := hmac.New(sha1.New, hkey)
	mac.Write(data)
	return mac.Sum(nil)[:obfsHMACSHA1Len]
}

// handshakeFinish 生成 43 字节客户端 auth 记录。
func (t *tlsObfs) handshakeFinish() []byte {
	data := make([]byte, 43)
	copy(data, []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x20})
	_, _ = rand.Read(data[11:33])
	copy(data[33:], t.hmacSHA1(data[:33]))
	return data
}

// encode 把 SSR 密文包成 TLS 记录。首次调用会先补发客户端 auth 记录。
func (t *tlsObfs) encode(data []byte) []byte {
	if !t.tls {
		return data
	}
	var out []byte
	if !t.finishSent {
		out = append(out, t.handshakeFinish()...)
		t.finishSent = true
	}
	return append(out, t.packAppData(data)...)
}

func (t *tlsObfs) packAppData(data []byte) []byte {
	var out []byte
	for len(data) > 0 {
		n := len(data)
		if n > 1024 {
			n = randInt(4096) + 100
			if n > len(data) {
				n = len(data)
			}
		}
		hdr := []byte{0x17, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(hdr[3:5], uint16(n&0xFFFF))
		out = append(out, hdr...)
		out = append(out, data[:n]...)
		data = data[n:]
	}
	return out
}

// decode 从原始 TCP 字节流中剥离 TLS 记录层，返回内部 SSR 密文。
// 服务端 auth 记录（0x14 开头，43 字节）会被跳过而不校验。
func (t *tlsObfs) decode(raw []byte) []byte {
	if !t.tls {
		return raw
	}
	t.decodeMu.Lock()
	defer t.decodeMu.Unlock()
	t.rbuf = append(t.rbuf, raw...)
	var out []byte
	for len(t.rbuf) > 0 {
		switch t.rbuf[0] {
		case 0x17, 0x16: // application data / handshake record
			if len(t.rbuf) < 5 {
				return out
			}
			n := int(binary.BigEndian.Uint16(t.rbuf[3:5]))
			if len(t.rbuf) < 5+n {
				return out
			}
			if t.rbuf[0] == 0x17 {
				out = append(out, t.rbuf[5:5+n]...)
			}
			t.rbuf = t.rbuf[5+n:]
		case 0x14: // ChangeCipherSpec + auth，固定 43 字节
			if len(t.rbuf) < 43 {
				return out
			}
			t.rbuf = t.rbuf[43:]
		default:
			// 无法识别：丢弃 1 字节重新同步。
			t.rbuf = t.rbuf[1:]
		}
	}
	return out
}

// clientHello 构造 TLS 1.2 ClientHello 记录（含 SNI 与 session ticket 扩展）。
func (t *tlsObfs) clientHello() []byte {
	if !t.tls {
		return nil
	}
	tlsData0 := []byte("\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00")
	tlsData1 := []byte("\xff\x01\x00\x01\x00")
	tlsData2 := []byte("\x00\x17\x00\x00\x00\x23\x00\xd0")
	tlsData3 := []byte("\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18\x00\x15\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	var tlsData [2048]byte
	tlsDataLen := 0
	copy(tlsData[0:], tlsData1)
	tlsDataLen += len(tlsData1)
	sni := t.sni(t.host)
	copy(tlsData[tlsDataLen:], sni)
	tlsDataLen += len(sni)
	copy(tlsData[tlsDataLen:], tlsData2)
	tlsDataLen += len(tlsData2)

	ticketLen := randInt(164)*2 + 64
	tlsData[tlsDataLen-1] = byte(ticketLen & 0xFF)
	tlsData[tlsDataLen-2] = byte(ticketLen >> 8)
	_, _ = rand.Read(tlsData[tlsDataLen : tlsDataLen+ticketLen])
	tlsDataLen += ticketLen
	copy(tlsData[tlsDataLen:], tlsData3)
	tlsDataLen += len(tlsData3)

	length := 11 + 32 + 1 + 32 + len(tlsData0) + 2 + tlsDataLen
	encoded := make([]byte, length)
	pdata := length - tlsDataLen
	l := tlsDataLen
	copy(encoded[pdata:], tlsData[:tlsDataLen])
	encoded[pdata-1] = byte(tlsDataLen)
	encoded[pdata-2] = byte(tlsDataLen >> 8)
	pdata -= 2
	l += 2

	copy(encoded[pdata-len(tlsData0):], tlsData0)
	pdata -= len(tlsData0)
	l += len(tlsData0)

	copy(encoded[pdata-32:], t.clientID[:])
	pdata -= 32
	l += 32
	encoded[pdata-1] = 0x20
	pdata -= 1
	l += 1

	auth := make([]byte, 32)
	binary.BigEndian.PutUint32(auth[0:4], uint32(time.Now().Unix()))
	_, _ = rand.Read(auth[4:22])
	copy(auth[22:], t.hmacSHA1(auth[:22]))
	copy(encoded[pdata-32:], auth)
	pdata -= 32
	l += 32

	encoded[pdata-1] = 0x03
	encoded[pdata-2] = 0x03
	pdata -= 2
	l += 2

	encoded[pdata-1] = byte(l)
	encoded[pdata-2] = byte(l >> 8)
	encoded[pdata-3] = 0
	encoded[pdata-4] = 1
	pdata -= 4
	l += 4

	encoded[pdata-1] = byte(l)
	encoded[pdata-2] = byte(l >> 8)
	pdata -= 2
	l += 2

	encoded[pdata-1] = 0x01
	encoded[pdata-2] = 0x03
	pdata -= 2
	l += 2

	encoded[pdata-1] = 0x16
	return encoded
}

func (t *tlsObfs) sni(u string) []byte {
	b := []byte(u)
	length := len(b)
	ret := make([]byte, length+9)
	copy(ret[9:], b)
	binary.BigEndian.PutUint16(ret[7:], uint16(length&0xFFFF))
	length += 3
	binary.BigEndian.PutUint16(ret[4:], uint16(length&0xFFFF))
	length += 2
	binary.BigEndian.PutUint16(ret[2:], uint16(length&0xFFFF))
	return ret
}
