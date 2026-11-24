// Package vision 实现 VLESS flow `xtls-rprx-vision` 的 padding 子协议。
//
// wire 格式（每个 Vision 帧，参考 mihomo transport/vless/vision/padding.go）：
//
//	首帧: [UUID 16][cmd 1][contentLen 2 BE][paddingLen 2 BE][content][padding]
//	后续帧: [cmd 1][contentLen 2 BE][paddingLen 2 BE][content][padding]
//
// cmd: 0x00=continue, 0x01=end, 0x02=direct
// 首帧含完整 16 字节 UUID，后续帧只有 5 字节头（cmd+len+padLen）。
//
// 本包纯标准库实现，不依赖 mihomo 的 unsafe/reflect hack：
// 我们的 Reality 是自建 tls13Conn，明文数据经过本包读写，
// 因此直接在明文层加/解 Vision padding 即可。
package vision

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	HeaderLen    = 21 // 16(UUID) + 1(cmd) + 2(contentLen) + 2(paddingLen)
	SubHeaderLen = 5  // 后续帧：1 + 2 + 2

	CommandContinue byte = 0x00
	CommandEnd      byte = 0x01
	CommandDirect   byte = 0x02
)

var tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}

// isTLSApplicationData 判断一段明文是否以 TLS Application Data 记录头开头。
// Vision 用它判断何时停止 padding、切换到 direct 模式。
func isTLSApplicationData(p []byte) bool {
	return len(p) >= 3 && p[0] == 0x17 && p[1] == 0x03 && p[2] == 0x03
}

// frame 是一条 Vision 帧的解析结果。
type frame struct {
	Command     byte
	ContentLen  int
	PaddingLen  int
	HasUUID     bool
	UUID        [16]byte
	content     []byte
	totalHeader int
}

// parseHeader 从 b 的前部解析一条 Vision 帧头。
// first=true 表示期望首帧（含 16 字节 UUID）。
func parseHeader(b []byte, first bool) (frame, bool) {
	need := SubHeaderLen
	if first {
		need = HeaderLen
	}
	if len(b) < need {
		return frame{}, false
	}
	var f frame
	off := 0
	if first {
		copy(f.UUID[:], b[:16])
		f.HasUUID = true
		off = 16
	}
	f.Command = b[off]
	f.ContentLen = int(binary.BigEndian.Uint16(b[off+1 : off+3]))
	f.PaddingLen = int(binary.BigEndian.Uint16(b[off+3 : off+5]))
	f.totalHeader = need
	return f, true
}

// buildFrame 把 content 封装成一条 Vision 帧。
// first=true 时写入 16 字节 UUID（writeUUID 非空）；否则只写 5 字节子头。
// paddingTLS=true 时给短内容加长 padding（隐藏 VLESS header）。
func buildFrame(content []byte, cmd byte, uuid []byte, first, paddingTLS bool) []byte {
	var paddingLen int
	if len(content) < 900 {
		if paddingTLS {
			// 长 padding：900..1399 字节（mihomo: 900 + rand(500) - contentLen）
			var b [2]byte
			_, _ = rand.Read(b[:])
			extra := int(binary.BigEndian.Uint16(b[:])) % 500
			paddingLen = 900 + extra - len(content)
		} else {
			var b [2]byte
			_, _ = rand.Read(b[:])
			paddingLen = int(binary.BigEndian.Uint16(b[:])) % 256
		}
	}
	if paddingLen < 0 {
		paddingLen = 0
	}
	headerLen := SubHeaderLen
	if first {
		headerLen = HeaderLen
	}
	out := make([]byte, 0, headerLen+len(content)+paddingLen)
	if first {
		if len(uuid) >= 16 {
			out = append(out, uuid[:16]...)
		} else {
			out = append(out, make([]byte, 16)...)
		}
	}
	out = append(out, cmd)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(content)))
	out = append(out, l[:]...)
	binary.BigEndian.PutUint16(l[:], uint16(paddingLen))
	out = append(out, l[:]...)
	out = append(out, content...)
	if paddingLen > 0 {
		pad := make([]byte, paddingLen)
		_, _ = rand.Read(pad)
		out = append(out, pad...)
	}
	return out
}
