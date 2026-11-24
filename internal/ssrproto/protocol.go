package ssrproto

// 本文件实现 SSR 协议插件。当前完整实现 auth_sha1_v4 / auth_sha1_v4_compatible，
// 其余协议名（auth_aes128_md5 / auth_chain_a 等）会被识别但按 origin 处理，详见 README/包注释。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"net"
	"strings"
	"time"
)

const obfsHMACSHA1Len = 10 // SSR 各插件统一使用的 HMAC-SHA1 截断长度

// authState 保存 auth_sha1_v4 的连接状态（client id / connection id / 是否已发头部）。
type authState struct {
	enabled    bool
	compatible bool
	connID     uint32
	clientID   []byte
	sentHeader bool
}

func newAuthState(protocol, password, param string) *authState {
	name := strings.ToLower(strings.TrimSpace(protocol))
	a := &authState{}
	switch name {
	case "auth_sha1_v4", "auth_sha1_v4_compatible":
		a.enabled = true
		a.compatible = name == "auth_sha1_v4_compatible"
	default:
		// 其余协议暂未实现，退化为不带协议封装的 origin  framing。
		return a
	}
	// protocol_param 形如 "user_id:passwd" 时，取 ':' 前的 user id 作 client id（多用户）。
	if i := strings.IndexAny(param, ":#"); i > 0 {
		a.clientID = []byte(param[:i])
	}
	if len(a.clientID) == 0 {
		a.clientID, _ = randBytes(8)
	}
	b, _ := randBytes(4)
	a.connID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	return a
}

// preEncrypt 在 SS 加密之前对明文（地址头 + 业务数据）做协议封装。
// addrHeader 只会在第一次调用时写入。
func (a *authState) preEncrypt(b, addrHeader, key, iv []byte) []byte {
	if !a.enabled {
		if !a.sentHeader {
			a.sentHeader = true
			return append(append([]byte(nil), addrHeader...), b...)
		}
		return append([]byte(nil), b...)
	}
	plain := b
	if !a.sentHeader {
		plain = append(append([]byte(nil), addrHeader...), b...)
	}
	var out []byte
	if !a.sentHeader {
		// 头部包只封装地址头（最多 30 字节），余下数据按普通数据块封装。
		head := getHeadSize(plain, 30)
		if head > len(plain) {
			head = len(plain)
		}
		out = append(out, a.packAuthData(plain[:head], key, iv)...)
		out = append(out, a.packChunks(plain[head:])...)
		a.sentHeader = true
	} else {
		out = a.packChunks(plain)
	}
	return out
}

// postDecrypt 对 SS 解密后的数据做协议解封装，返回明文。
func (a *authState) postDecrypt(data []byte) []byte {
	if !a.enabled {
		return data
	}
	var out []byte
	for len(data) > 4 {
		if binary.LittleEndian.Uint16(data[2:4]) != uint16(calcCRC32(data, 2)) {
			// 不匹配的块，原样保留，避免误伤。
			break
		}
		length := int(binary.BigEndian.Uint16(data[0:2]))
		if length >= 8192 || length < 8 || length > len(data) {
			break
		}
		if !checkAdler32(data, length) {
			break
		}
		pos := int(data[4])
		if pos == 0xFF {
			pos = int(binary.BigEndian.Uint16(data[5:7])) + 4
		} else {
			pos += 4
		}
		if pos+4 > length {
			break
		}
		out = append(out, data[pos:length-4]...)
		data = data[length:]
	}
	return out
}

func (a *authState) packChunks(data []byte) []byte {
	var out []byte
	const blockSize = 4096
	for len(data) > blockSize {
		out = append(out, a.packData(data[:blockSize])...)
		data = data[blockSize:]
	}
	if len(data) > 0 {
		out = append(out, a.packData(data)...)
	}
	return out
}

// packData 封装一个 auth_sha1_v4 数据块：
// [len:2][crc16(len):2][randlen:1(+2)][rand][data][adler32:4]
func (a *authState) packData(data []byte) []byte {
	randLen := 1
	switch {
	case len(data) <= 400:
		randLen += randInt(1024)
	case len(data) <= 1300:
		randLen += randInt(128)
	}
	outLen := randLen + len(data) + 8
	out := make([]byte, outLen)
	binary.BigEndian.PutUint16(out[0:2], uint16(outLen&0xFFFF))
	binary.LittleEndian.PutUint16(out[2:4], uint16(calcCRC32(out, 2)))
	fillStart := 5
	if randLen < 128 {
		out[4] = byte(randLen)
	} else {
		out[4] = 0xFF
		binary.BigEndian.PutUint16(out[5:7], uint16(randLen&0xFFFF))
		fillStart = 7
	}
	// randlen 头与数据之间的填充字节（数据落在 randLen+4）。
	if fillStart < randLen+4 {
		_, _ = rand.Read(out[fillStart : randLen+4])
	}
	copy(out[randLen+4:], data)
	binary.LittleEndian.PutUint32(out[outLen-4:], adler32.Checksum(out[:outLen-4]))
	return out
}

// packAuthData 封装 auth_sha1_v4 的握手/首包：
// [len:2][crc32(len+salt+key):4][randlen:1(+2)][rand][ts:4][clientID:4][connID:4][data][hmac:10]
func (a *authState) packAuthData(data, key, iv []byte) []byte {
	randLen := 1
	switch {
	case len(data) <= 400:
		randLen += randInt(1024)
	case len(data) <= 1300:
		randLen += randInt(128)
	}
	dataOffset := randLen + 4 + 2
	outLen := dataOffset + len(data) + 12 + obfsHMACSHA1Len
	out := make([]byte, outLen)

	a.connID++
	if a.connID > 0xFF000000 {
		a.clientID, _ = randBytes(8)
	}
	if len(a.clientID) < 4 {
		a.clientID = append(a.clientID, make([]byte, 4-len(a.clientID))...)
	}

	binary.BigEndian.PutUint16(out[0:2], uint16(outLen&0xFFFF))

	// crc = CRC32( len(2) || "auth_sha1_v4" || key )
	crcData := make([]byte, 2+len(saltAuthSHA1V4)+len(key))
	copy(crcData[0:2], out[0:2])
	copy(crcData[2:], saltAuthSHA1V4)
	copy(crcData[2+len(saltAuthSHA1V4):], key)
	binary.LittleEndian.PutUint32(out[2:6], calcCRC32(crcData, len(crcData)))

	// 随机段：先填随机数，再写 randlen 头（与 shadowsocksr 行为一致）。
	_, _ = rand.Read(out[6:dataOffset])
	if randLen < 128 {
		out[6] = byte(randLen)
	} else {
		out[6] = 0xFF
		binary.BigEndian.PutUint16(out[7:9], uint16(randLen&0xFFFF))
	}

	binary.LittleEndian.PutUint32(out[dataOffset:dataOffset+4], uint32(time.Now().Unix()))
	copy(out[dataOffset+4:dataOffset+8], a.clientID[:4])
	binary.LittleEndian.PutUint32(out[dataOffset+8:dataOffset+12], a.connID)
	copy(out[dataOffset+12:], data)

	hkey := make([]byte, 0, len(iv)+len(key))
	hkey = append(hkey, iv...)
	hkey = append(hkey, key...)
	mac := hmac.New(sha1.New, hkey)
	mac.Write(out[:outLen-obfsHMACSHA1Len])
	copy(out[outLen-obfsHMACSHA1Len:], mac.Sum(nil)[:obfsHMACSHA1Len])
	return out
}

var saltAuthSHA1V4 = []byte("auth_sha1_v4")

// getHeadSize 返回 SOCKS5 地址头长度，maxSize 为域名地址的上限。
func getHeadSize(data []byte, maxSize int) int {
	if len(data) == 0 {
		return maxSize
	}
	switch data[0] {
	case 1: // IPv4
		return 7
	case 4: // IPv6
		return 19
	case 3: // 域名
		if len(data) < 2 {
			return maxSize
		}
		n := int(data[1]) + 2
		if n > maxSize {
			return maxSize
		}
		return n
	default:
		return maxSize
	}
}

func checkAdler32(data []byte, length int) bool {
	if length < 4 || length > len(data) {
		return false
	}
	return adler32.Checksum(data[:length-4]) == binary.LittleEndian.Uint32(data[length-4:length])
}

// encodeAddr 把 host:port 编码成 SOCKS5 ATYP+ADDR+PORT，作为 SSR 明文地址头。
func encodeAddr(host string, port uint16) []byte {
	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 1)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 4)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		buf = append(buf, 3, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}
