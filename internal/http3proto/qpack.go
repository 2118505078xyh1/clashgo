package http3proto

import (
	"errors"
	"fmt"
	"io"
)

// QPACK（RFC 9204）的最小实现：只使用静态表和 literal 表示，不使用动态表，
// 也不在 encoder stream 上发任何指令。这样编码出的 header block 不依赖任何
// 连接级压缩状态，服务端即使没有收到 encoder stream 也能解码。
//
// 关于 encoder stream 的研究结论（见 doc.go）：RFC 9204 Section 3.2.3 规定，
// 当 SETTINGS_QPACK_MAX_TABLE_CAPACITY 为 0 时，encoder MUST NOT 发送任何
// encoder stream 指令；Section 4.2 允许在不使用动态表时不创建 encoder stream。
// 本包向服务端声明的动态表容量为 0，因此**不**打开 encoder stream，也**不**
// 发送所谓「Set Dynamic Table Capacity = 0」指令。任务描述中猜测的 0x3f/0x00
// 也不是该指令的编码：该指令前缀是 '001'（3 bit），容量 0 的字节是 0x20。

// HeaderField 是一个 name/value 对（QPACK 中的 field line）。
type HeaderField struct {
	Name  string
	Value string
}

// HeaderField 的静态表（RFC 9204 Appendix A，共 99 项，索引从 0 开始）。
// 注意：:method POST 的索引是 20，:scheme https 是 23，:path "/" 是 1，
// :authority（空值）是 0 —— 与任务描述里的猜测（17）不同，已按 RFC 核实。
var qpackStaticTable = [99]HeaderField{
	{":authority", ""},
	{":path", "/"},
	{"age", "0"},
	{"content-disposition", ""},
	{"content-length", "0"},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"referer", ""},
	{"set-cookie", ""},
	{":method", "CONNECT"},
	{":method", "DELETE"},
	{":method", "GET"},
	{":method", "HEAD"},
	{":method", "OPTIONS"},
	{":method", "POST"},
	{":method", "PUT"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "103"},
	{":status", "200"},
	{":status", "304"},
	{":status", "404"},
	{":status", "503"},
	{"accept", "*/*"},
	{"accept", "application/dns-message"},
	{"accept-encoding", "gzip, deflate, br"},
	{"accept-ranges", "bytes"},
	{"access-control-allow-headers", "cache-control"},
	{"access-control-allow-headers", "content-type"},
	{"access-control-allow-origin", "*"},
	{"cache-control", "max-age=0"},
	{"cache-control", "max-age=2592000"},
	{"cache-control", "max-age=604800"},
	{"cache-control", "no-cache"},
	{"cache-control", "no-store"},
	{"cache-control", "public, max-age=31536000"},
	{"content-encoding", "br"},
	{"content-encoding", "gzip"},
	{"content-type", "application/dns-message"},
	{"content-type", "application/javascript"},
	{"content-type", "application/json"},
	{"content-type", "application/x-www-form-urlencoded"},
	{"content-type", "image/gif"},
	{"content-type", "image/jpeg"},
	{"content-type", "image/png"},
	{"content-type", "text/css"},
	{"content-type", "text/html; charset=utf-8"},
	{"content-type", "text/plain"},
	{"content-type", "text/plain;charset=utf-8"},
	{"range", "bytes=0-"},
	{"strict-transport-security", "max-age=31536000"},
	{"strict-transport-security", "max-age=31536000; includesubdomains"},
	{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
	{"vary", "accept-encoding"},
	{"vary", "origin"},
	{"x-content-type-options", "nosniff"},
	{"x-xss-protection", "1; mode=block"},
	{":status", "100"},
	{":status", "204"},
	{":status", "206"},
	{":status", "302"},
	{":status", "400"},
	{":status", "403"},
	{":status", "421"},
	{":status", "425"},
	{":status", "500"},
	{"accept-language", ""},
	{"access-control-allow-credentials", "FALSE"},
	{"access-control-allow-credentials", "TRUE"},
	{"access-control-allow-headers", "*"},
	{"access-control-allow-methods", "get"},
	{"access-control-allow-methods", "get, post, options"},
	{"access-control-allow-methods", "options"},
	{"access-control-expose-headers", "content-length"},
	{"access-control-request-headers", "content-type"},
	{"access-control-request-method", "get"},
	{"access-control-request-method", "post"},
	{"alt-svc", "clear"},
	{"authorization", ""},
	{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{"early-data", "1"},
	{"expect-ct", ""},
	{"forwarded", ""},
	{"if-range", ""},
	{"origin", ""},
	{"purpose", "prefetch"},
	{"server", ""},
	{"timing-allow-origin", "*"},
	{"upgrade-insecure-requests", "1"},
	{"user-agent", ""},
	{"x-forwarded-for", ""},
	{"x-frame-options", "deny"},
	{"x-frame-options", "sameorigin"},
}

var (
	// ErrDynamicTableRef 表示遇到动态表引用（本包不支持动态表）。
	ErrDynamicTableRef = errors.New("http3proto: dynamic table reference not supported")
	// ErrBadFieldSection 表示 QPACK encoded field section 格式非法。
	ErrBadFieldSection = errors.New("http3proto: bad QPACK field section")
)

// staticFieldIndex 返回与 name/value 完全相同的静态表索引。
func staticFieldIndex(name, value string) (int, bool) {
	for i, e := range qpackStaticTable {
		if e.Name == name && e.Value == value {
			return i, true
		}
	}
	return 0, false
}

// staticNameIndex 返回名字匹配的第一个静态表索引（只取名字，不要求值相同）。
func staticNameIndex(name string) (int, bool) {
	for i, e := range qpackStaticTable {
		if e.Name == name {
			return i, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// QPACK 原语
// ---------------------------------------------------------------------------

// appendPrefixedInt 追加一个 HPACK/QPACK 前缀整数。
// hi 是整数最高 N 位之外、已经占用的首字节高位（表示类型/标志）。
// RFC 9204 Section 4.1.1：当且仅当 v < 2^N-1 时直接编码，否则前缀全 1 后接
// 7 bit 一组的续字节（最高位为续标志）。
func appendPrefixedInt(dst []byte, v uint64, n uint, hi byte) []byte {
	max := uint64(1)<<n - 1
	if v < max {
		return append(dst, hi|byte(v))
	}
	dst = append(dst, hi|byte(max))
	v -= max
	for v >= 128 {
		dst = append(dst, byte(v%128)|0x80)
		v /= 128
	}
	return append(dst, byte(v))
}

// appendStringLiteral 追加一个 N-bit prefix string literal（RFC 9204 Section 4.1.2）。
// leading 是首字节中在该字符串之前的位（8-N 位），huffman 决定 H 标志。
func appendStringLiteral(dst []byte, s string, huffman bool, leading byte, n uint) []byte {
	data := []byte(s)
	if huffman {
		data = HuffmanEncode(data)
	}
	hi := leading
	if huffman {
		hi |= 1 << (n - 1) // H 标志位于字符串前缀的最高位
	}
	dst = appendPrefixedInt(dst, uint64(len(data)), n-1, hi)
	return append(dst, data...)
}

// bitReader 用于在 QPACK field line 的任意 bit 边界读取整数和字符串。
type bitReader struct {
	data []byte
	bit  int // 下一个待读 bit 的索引（从 0 起，MSB 优先）
}

func (r *bitReader) remaining() int { return len(r.data)*8 - r.bit }

func (r *bitReader) readBit() (byte, error) {
	if r.bit >= len(r.data)*8 {
		return 0, io.ErrUnexpectedEOF
	}
	b := (r.data[r.bit>>3] >> uint(7-(r.bit&7))) & 1
	r.bit++
	return b, nil
}

func (r *bitReader) readBits(n int) (uint64, error) {
	var v uint64
	for i := 0; i < n; i++ {
		b, err := r.readBit()
		if err != nil {
			return 0, err
		}
		v = v<<1 | uint64(b)
	}
	return v, nil
}

// readPrefixedInt 在当前 bit 位置读取一个 N-bit 前缀整数。
func (r *bitReader) readPrefixedInt(n uint) (uint64, error) {
	initial, err := r.readBits(int(n))
	if err != nil {
		return 0, err
	}
	max := uint64(1)<<n - 1
	if initial < max {
		return initial, nil
	}
	var v uint64
	var shift uint
	for {
		b, err := r.readBits(8)
		if err != nil {
			return 0, err
		}
		if shift > 62 {
			return 0, fmt.Errorf("%w: integer too long", ErrBadFieldSection)
		}
		v |= uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	return max + v, nil
}

// readStringLiteral 读取一个 N-bit prefix string literal，返回解码后的字节。
func (r *bitReader) readStringLiteral(n uint) ([]byte, error) {
	h, err := r.readBit()
	if err != nil {
		return nil, err
	}
	length, err := r.readPrefixedInt(n - 1)
	if err != nil {
		return nil, err
	}
	if length > uint64(len(r.data)) {
		return nil, fmt.Errorf("%w: string length %d", ErrBadFieldSection, length)
	}
	start := (r.bit + 7) / 8
	end := start + int(length)
	if end > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	raw := r.data[start:end]
	r.bit = end * 8
	if h == 0 {
		return append([]byte(nil), raw...), nil
	}
	return HuffmanDecode(raw)
}

// ---------------------------------------------------------------------------
// Encoded field section
// ---------------------------------------------------------------------------

// EncodeFieldSection 把一组 field line 编码成 QPACK encoded field section。
//
// 字段按输入顺序编码。section prefix 的 Required Insert Count = 0、Base = 0，
// 表示完全不使用动态表。编码策略：
//   - 静态表中 name+value 完全匹配 → Indexed Field Line（表示 1）
//   - 只有 name 匹配静态表 → Literal Field Line with Name Reference（表示 4）
//   - 都不匹配 → Literal Field Line with Literal Name（表示 6）
//
// 所有 literal 的 N 位都设为 1（never-indexed），保证认证值不会被中间节点写入
// 动态表；字符串一律使用静态 Huffman 编码。
func EncodeFieldSection(fields []HeaderField) []byte {
	return encodeFieldSection(fields, true, true)
}

// encodeFieldSection 是编码器的可配置内核，便于用 RFC 向量做 known-answer 测试：
// huffman 控制字符串是否做 Huffman 编码，neverIndex 控制 literal 的 N 位。
func encodeFieldSection(fields []HeaderField, huffman, neverIndex bool) []byte {
	// Encoded Field Section Prefix：RequiredInsertCount(8+) = 0，S=0, DeltaBase(7+) = 0
	b := appendPrefixedInt(nil, 0, 8, 0)
	b = appendPrefixedInt(b, 0, 7, 0)

	nBit := byte(0)
	if neverIndex {
		nBit = 1
	}
	for _, f := range fields {
		if idx, ok := staticFieldIndex(f.Name, f.Value); ok {
			// Indexed Field Line: '1' T=1 Index(6+)
			b = appendPrefixedInt(b, uint64(idx), 6, 0xc0)
			continue
		}
		if idx, ok := staticNameIndex(f.Name); ok {
			// Literal Field Line with Name Reference: '01' N T=1 NameIndex(4+)
			b = appendPrefixedInt(b, uint64(idx), 4, 0x50|nBit<<5)
		} else {
			// Literal Field Line with Literal Name: '001' N H NameLen(3+)
			// 名字是 4-bit prefix string literal，其 H 位在首字节 bit3。
			b = appendStringLiteral(b, f.Name, huffman, 0x20|nBit<<4, 4)
		}
		// 值都是 8-bit prefix string literal
		b = appendStringLiteral(b, f.Value, huffman, 0, 8)
	}
	return b
}

// DecodeFieldSection 解码 QPACK encoded field section。
// 本实现只支持静态表与 literal；遇到动态表引用返回 ErrDynamicTableRef。
func DecodeFieldSection(data []byte) ([]HeaderField, error) {
	r := &bitReader{data: data}
	reqInsert, err := r.readPrefixedInt(8)
	if err != nil {
		return nil, err
	}
	if reqInsert != 0 {
		return nil, fmt.Errorf("%w: RequiredInsertCount=%d", ErrDynamicTableRef, reqInsert)
	}
	sign, err := r.readBit()
	if err != nil {
		return nil, err
	}
	deltaBase, err := r.readPrefixedInt(7)
	if err != nil {
		return nil, err
	}
	// 本实现不使用动态表，但仍按 RFC 9204 Section 4.5.1.2 校验 Base 非负。
	if sign == 1 && reqInsert <= deltaBase {
		return nil, fmt.Errorf("%w: negative Base", ErrBadFieldSection)
	}

	var fields []HeaderField
	for r.remaining() > 0 {
		first, err := r.readBit()
		if err != nil {
			return nil, err
		}
		if first == 1 {
			// Indexed Field Line
			t, err := r.readBit()
			if err != nil {
				return nil, err
			}
			idx, err := r.readPrefixedInt(6)
			if err != nil {
				return nil, err
			}
			if t == 0 {
				return nil, ErrDynamicTableRef
			}
			f, err := staticEntry(idx)
			if err != nil {
				return nil, err
			}
			fields = append(fields, f)
			continue
		}
		second, err := r.readBit()
		if err != nil {
			return nil, err
		}
		if second == 1 {
			// Literal Field Line with Name Reference: '01' N T NameIndex(4+)
			if _, err := r.readBit(); err != nil { // N 位
				return nil, err
			}
			t, err := r.readBit()
			if err != nil {
				return nil, err
			}
			idx, err := r.readPrefixedInt(4)
			if err != nil {
				return nil, err
			}
			if t == 0 {
				return nil, ErrDynamicTableRef
			}
			nameEntry, err := staticEntry(idx)
			if err != nil {
				return nil, err
			}
			value, err := r.readStringLiteral(8)
			if err != nil {
				return nil, err
			}
			fields = append(fields, HeaderField{nameEntry.Name, string(value)})
			continue
		}
		third, err := r.readBit()
		if err != nil {
			return nil, err
		}
		if third == 1 {
			// Literal Field Line with Literal Name: '001' N H NameLen(3+)
			if _, err := r.readBit(); err != nil { // N 位
				return nil, err
			}
			name, err := r.readStringLiteral(4)
			if err != nil {
				return nil, err
			}
			value, err := r.readStringLiteral(8)
			if err != nil {
				return nil, err
			}
			fields = append(fields, HeaderField{string(name), string(value)})
			continue
		}
		fourth, err := r.readBit()
		if err != nil {
			return nil, err
		}
		// 剩下两种表示都引用动态表（Post-Base），本实现不支持。
		_ = fourth
		return nil, ErrDynamicTableRef
	}
	if r.bit%8 != 0 {
		return nil, fmt.Errorf("%w: trailing bits", ErrBadFieldSection)
	}
	return fields, nil
}

func staticEntry(idx uint64) (HeaderField, error) {
	if idx >= uint64(len(qpackStaticTable)) {
		return HeaderField{}, fmt.Errorf("%w: static index %d out of range", ErrBadFieldSection, idx)
	}
	return qpackStaticTable[idx], nil
}
