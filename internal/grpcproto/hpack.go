package grpcproto

// HPACK (RFC 7541) 的最小实现，仅依赖标准库。
//
// 编码侧只使用静态表索引 + raw literal（不做 Huffman，符合 RFC，且服务端必须支持）；
// 解码侧支持完整的静态表、动态表（增量索引 / 索引名 / 动态表大小更新）以及
// Huffman 编码的字符串——真实的 grpc-go 默认会用 Huffman 编码响应头，
// 因此解码侧必须支持，否则无法与真实服务端互通。

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// HeaderField 是一个 HPACK 头部字段。Sensitive 为真时使用 never-indexed
// 表示，避免中间节点把它写入动态表。
type HeaderField struct {
	Name      string
	Value     string
	Sensitive bool
}

// staticTable 是 RFC 7541 Appendix A 的 61 项静态表。索引从 1 开始。
var staticTable = [...]HeaderField{
	{Name: ":authority"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "POST"},
	{Name: ":path", Value: "/"},
	{Name: ":path", Value: "/index.html"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "500"},
	{Name: "accept-charset"},
	{Name: "accept-encoding", Value: "gzip, deflate"},
	{Name: "accept-language"},
	{Name: "accept-ranges"},
	{Name: "accept"},
	{Name: "access-control-allow-origin"},
	{Name: "age"},
	{Name: "allow"},
	{Name: "authorization"},
	{Name: "cache-control"},
	{Name: "content-disposition"},
	{Name: "content-encoding"},
	{Name: "content-language"},
	{Name: "content-length"},
	{Name: "content-location"},
	{Name: "content-range"},
	{Name: "content-type"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "expect"},
	{Name: "expires"},
	{Name: "from"},
	{Name: "host"},
	{Name: "if-match"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "if-range"},
	{Name: "if-unmodified-since"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "max-forwards"},
	{Name: "proxy-authenticate"},
	{Name: "proxy-authorization"},
	{Name: "range"},
	{Name: "referer"},
	{Name: "refresh"},
	{Name: "retry-after"},
	{Name: "server"},
	{Name: "set-cookie"},
	{Name: "strict-transport-security"},
	{Name: "transfer-encoding"},
	{Name: "user-agent"},
	{Name: "vary"},
	{Name: "via"},
	{Name: "www-authenticate"},
}

const (
	hpackStaticLen     = len(staticTable)
	hpackDefaultMaxTab = 4096
)

var errHpackIndex = errors.New("hpack: invalid index")

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

// EncodeHeaders 把一组头部字段编码成 HPACK block。
//
// 使用静态表精确匹配（整字段索引）、静态表名字匹配（literal without
// indexing / never indexed）或全新的 raw literal。不使用 Huffman，因此
// 输出的 block 可被任何遵循 RFC 7541 的解码器接受。
func EncodeHeaders(fields []HeaderField) []byte {
	var out []byte
	for _, f := range fields {
		if idx := exactStaticIndex(f.Name, f.Value); idx != 0 && !f.Sensitive {
			out = appendVarInt(out, 7, 0x80, uint32(idx))
			continue
		}
		nameIdx := staticNameIndex(f.Name)
		if f.Sensitive {
			// 6.2.3 never indexed（4 位前缀）。
			out = appendVarInt(out, 4, 0x10, uint32(nameIdx))
			if nameIdx == 0 {
				out = appendString(out, f.Name)
			}
		} else if nameIdx != 0 {
			// 6.2.1 incremental indexing（6 位前缀），与 RFC 示例一致。
			out = appendVarInt(out, 6, 0x40, uint32(nameIdx))
		} else {
			// 6.2.2 without indexing，新名字（4 位前缀）。
			out = appendVarInt(out, 4, 0x00, 0)
			out = appendString(out, f.Name)
		}
		out = appendString(out, f.Value)
	}
	return out
}

func exactStaticIndex(name, value string) int {
	for i := range staticTable {
		if staticTable[i].Name == name && staticTable[i].Value == value {
			return i + 1
		}
	}
	return 0
}

func staticNameIndex(name string) int {
	// 同名项取索引最大者（RFC 建议），对静态表而言差别不大。
	for i := len(staticTable) - 1; i >= 0; i-- {
		if staticTable[i].Name == name {
			return i + 1
		}
	}
	return 0
}

// appendVarInt 编码 HPACK 整数：高位 prefix 占 prefixBits 位，低位放整数。
func appendVarInt(dst []byte, prefixBits uint8, prefix byte, n uint32) []byte {
	max := uint32(1<<prefixBits) - 1
	if n < max {
		return append(dst, prefix|byte(n))
	}
	dst = append(dst, prefix|byte(max))
	n -= max
	for n >= 128 {
		dst = append(dst, byte(n&0x7f)|0x80)
		n >>= 7
	}
	return append(dst, byte(n))
}

// appendString 编码一个不使用 Huffman 的 string literal（7 位长度前缀）。
func appendString(dst []byte, s string) []byte {
	dst = appendVarInt(dst, 7, 0, uint32(len(s)))
	return append(dst, s...)
}

// ---------------------------------------------------------------------------
// 解码
// ---------------------------------------------------------------------------

// Decoder 维护 HPACK 解码状态（主要是动态表）。一个 HTTP/2 连接上的所有
// header block（初始 HEADERS 与 trailers）必须共用同一个 Decoder 实例。
type Decoder struct {
	dyn        []HeaderField // 最新条目在最前
	dynSize    int
	maxDynSize int
}

// NewDecoder 创建一个 HPACK 解码器；maxSize 为允许的动态表大小上限。
func NewDecoder(maxSize int) *Decoder {
	if maxSize <= 0 || maxSize > hpackDefaultMaxTab {
		maxSize = hpackDefaultMaxTab
	}
	return &Decoder{maxDynSize: maxSize}
}

// DecodeHeaders 用一个全新的解码器解一个独立的 header block。
// 对不依赖跨 block 动态表的场景（测试、简单服务端）足够；与真实 gRPC
// 服务端通信时应使用 *Decoder.Decode 以保持动态表状态。
func DecodeHeaders(block []byte) ([]HeaderField, error) {
	return NewDecoder(hpackDefaultMaxTab).Decode(block)
}

// Decode 解码一个完整的 header block。
func (d *Decoder) Decode(block []byte) ([]HeaderField, error) {
	var out []HeaderField
	off := 0
	for off < len(block) {
		b := block[off]
		switch {
		case b&0x80 != 0:
			// 6.1 索引字段
			idx, used, err := readVarInt(block, off, 7)
			if err != nil {
				return nil, err
			}
			f, ok := d.at(idx)
			if !ok {
				return nil, fmt.Errorf("%w: %d", errHpackIndex, idx)
			}
			out = append(out, f)
			off += used
		case b&0xc0 == 0x40:
			// 6.2.1 增量索引
			f, used, err := d.parseLiteral(block, off, 6)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
			d.addDynamic(f)
			off += used
		case b&0xf0 == 0x00:
			// 6.2.2 不索引
			f, used, err := d.parseLiteral(block, off, 4)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
			off += used
		case b&0xf0 == 0x10:
			// 6.2.3 永不索引
			f, used, err := d.parseLiteral(block, off, 4)
			if err != nil {
				return nil, err
			}
			f.Sensitive = true
			out = append(out, f)
			off += used
		case b&0xe0 == 0x20:
			// 6.3 动态表大小更新
			n, used, err := readVarInt(block, off, 5)
			if err != nil {
				return nil, err
			}
			if n > hpackDefaultMaxTab {
				return nil, fmt.Errorf("hpack: dynamic table size %d too large", n)
			}
			if int(n) > d.maxDynSize {
				n = uint32(d.maxDynSize)
			}
			d.maxDynSize = int(n)
			d.evict()
			off += used
		default:
			return nil, fmt.Errorf("hpack: invalid representation byte %#x", b)
		}
	}
	return out, nil
}

// parseLiteral 解码一个 literal 表示，返回字段及消耗的字节数（相对 off）。
func (d *Decoder) parseLiteral(block []byte, off int, prefixBits uint8) (HeaderField, int, error) {
	start := off
	nameIdx, used, err := readVarInt(block, off, prefixBits)
	if err != nil {
		return HeaderField{}, 0, err
	}
	off += used
	var name string
	if nameIdx != 0 {
		f, ok := d.at(nameIdx)
		if !ok {
			return HeaderField{}, 0, fmt.Errorf("%w: name %d", errHpackIndex, nameIdx)
		}
		name = f.Name
	} else {
		name, used, err = readString(block, off)
		if err != nil {
			return HeaderField{}, 0, err
		}
		off += used
	}
	value, used, err := readString(block, off)
	if err != nil {
		return HeaderField{}, 0, err
	}
	off += used
	return HeaderField{Name: name, Value: value}, off - start, nil
}

func (d *Decoder) at(i uint32) (HeaderField, bool) {
	if i == 0 {
		return HeaderField{}, false
	}
	if int(i) <= hpackStaticLen {
		return staticTable[i-1], true
	}
	idx := int(i) - hpackStaticLen - 1
	if idx < 0 || idx >= len(d.dyn) {
		return HeaderField{}, false
	}
	return d.dyn[idx], true
}

func (d *Decoder) addDynamic(f HeaderField) {
	size := len(f.Name) + len(f.Value) + 32
	d.dyn = append([]HeaderField{f}, d.dyn...)
	d.dynSize += size
	d.evict()
}

func (d *Decoder) evict() {
	for d.dynSize > d.maxDynSize && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.dynSize -= len(last.Name) + len(last.Value) + 32
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
}

// readVarInt 从 block[off:] 解一个 HPACK 整数，返回值和消耗的字节数。
func readVarInt(block []byte, off int, prefixBits uint8) (uint32, int, error) {
	if off >= len(block) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	max := uint32(1<<prefixBits) - 1
	b := block[off]
	off++
	val := uint32(b & byte(max))
	if val < max {
		return val, 1, nil
	}
	var shift uint
	used := 1
	for {
		if off >= len(block) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		b = block[off]
		off++
		used++
		val += uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return 0, 0, errors.New("hpack: integer overflow")
		}
	}
	return val, used, nil
}

// readString 解码一个 string literal，返回字符串及消耗的字节数（相对 off）。
func readString(block []byte, off int) (string, int, error) {
	start := off
	if off >= len(block) {
		return "", 0, io.ErrUnexpectedEOF
	}
	huffman := block[off]&0x80 != 0
	n, used, err := readVarInt(block, off, 7)
	if err != nil {
		return "", 0, err
	}
	off += used
	if off > len(block) {
		return "", 0, io.ErrUnexpectedEOF
	}
	if n > uint32(len(block)-off) {
		return "", 0, io.ErrUnexpectedEOF
	}
	raw := block[off : off+int(n)]
	off += int(n)
	if !huffman {
		return string(raw), off - start, nil
	}
	s, err := huffmanDecode(raw)
	if err != nil {
		return "", 0, err
	}
	return s, off - start, nil
}

// ---------------------------------------------------------------------------
// Huffman 解码（RFC 7541 Appendix B）
// ---------------------------------------------------------------------------

// huffmanCodeLen / huffmanCodes 是 RFC 7541 Appendix B 的标准表。
// 仅内置数据，不导入任何外部包。
var huffmanCodeLen = [256]uint8{
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
}

var huffmanCodes = [256]uint32{
	0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6,
	0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd,
	0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1,
	0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7,
	0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa,
	0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17,
	0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c,
	0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60,
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
	0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
	0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
	0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8,
	0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd,
	0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
	0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd,
	0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0,
	0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8,
	0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda, 0x1fffdd,
	0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea,
	0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
	0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee,
	0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5,
	0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
	0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde,
	0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6,
	0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5,
	0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec,
	0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
	0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea,
	0x7ffff4, 0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8,
	0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee,
	0x7ffffef, 0x7fffff0, 0x3ffffee,
}

type huffNode struct {
	child [2]*huffNode
	sym   byte
	leaf  bool
	len   uint8
}

var (
	huffRootOnce sync.Once
	huffRoot     *huffNode
)

func getHuffRoot() *huffNode {
	huffRootOnce.Do(func() {
		root := &huffNode{}
		for sym := 0; sym < 256; sym++ {
			code := huffmanCodes[sym]
			length := huffmanCodeLen[sym]
			n := root
			for i := int(length) - 1; i >= 0; i-- {
				bit := (code >> uint(i)) & 1
				if n.child[bit] == nil {
					n.child[bit] = &huffNode{}
				}
				n = n.child[bit]
			}
			n.leaf = true
			n.sym = byte(sym)
			n.len = length
		}
		huffRoot = root
	})
	return huffRoot
}

var errInvalidHuffman = errors.New("hpack: invalid Huffman data")

func huffmanDecode(src []byte) (string, error) {
	root := getHuffRoot()
	var out strings.Builder
	n := root
	// 逐位读取，MSB 优先。
	for _, b := range src {
		for shift := 7; shift >= 0; shift-- {
			bit := (b >> uint(shift)) & 1
			n = n.child[bit]
			if n == nil {
				return "", errInvalidHuffman
			}
			if n.leaf {
				out.WriteByte(n.sym)
				n = root
			}
		}
	}
	// 末尾不足一个符号的填充位（RFC 允许 <=7 位的全 1 填充）直接忽略。
	return out.String(), nil
}

// 供测试使用的辅助：把 HeaderField 列表拼成 map，便于断言。
func headerFieldMap(fields []HeaderField) map[string]string {
	m := make(map[string]string, len(fields))
	for _, f := range fields {
		m[f.Name] = f.Value
	}
	return m
}
