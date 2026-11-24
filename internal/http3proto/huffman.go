package http3proto

// 本文件中的 Huffman 码表逐项抄录自 RFC 7541 Appendix B（HPACK Huffman Code）。
// RFC 9204 Section 4.1.2 明确规定 QPACK 使用完全相同的码表，不做任何修改。
// 每项是 {code, len}：code 为「右对齐（LSB）」的码值，len 为码长（bit）。
// 该项由脚本直接从 RFC 文本解析生成，避免人工抄录错误。

import (
	"errors"
	"fmt"
)

type huffCode struct {
	code   uint32
	length uint8
}

var huffmanCodes = [257]huffCode{
	{0x00001ff8, 13}, //   0
	{0x007fffd8, 23}, //   1
	{0x0fffffe2, 28}, //   2
	{0x0fffffe3, 28}, //   3
	{0x0fffffe4, 28}, //   4
	{0x0fffffe5, 28}, //   5
	{0x0fffffe6, 28}, //   6
	{0x0fffffe7, 28}, //   7
	{0x0fffffe8, 28}, //   8
	{0x00ffffea, 24}, //   9
	{0x3ffffffc, 30}, //  10
	{0x0fffffe9, 28}, //  11
	{0x0fffffea, 28}, //  12
	{0x3ffffffd, 30}, //  13
	{0x0fffffeb, 28}, //  14
	{0x0fffffec, 28}, //  15
	{0x0fffffed, 28}, //  16
	{0x0fffffee, 28}, //  17
	{0x0fffffef, 28}, //  18
	{0x0ffffff0, 28}, //  19
	{0x0ffffff1, 28}, //  20
	{0x0ffffff2, 28}, //  21
	{0x3ffffffe, 30}, //  22
	{0x0ffffff3, 28}, //  23
	{0x0ffffff4, 28}, //  24
	{0x0ffffff5, 28}, //  25
	{0x0ffffff6, 28}, //  26
	{0x0ffffff7, 28}, //  27
	{0x0ffffff8, 28}, //  28
	{0x0ffffff9, 28}, //  29
	{0x0ffffffa, 28}, //  30
	{0x0ffffffb, 28}, //  31
	{0x00000014, 6},  //  32
	{0x000003f8, 10}, //  33
	{0x000003f9, 10}, //  34
	{0x00000ffa, 12}, //  35
	{0x00001ff9, 13}, //  36
	{0x00000015, 6},  //  37
	{0x000000f8, 8},  //  38
	{0x000007fa, 11}, //  39
	{0x000003fa, 10}, //  40
	{0x000003fb, 10}, //  41
	{0x000000f9, 8},  //  42
	{0x000007fb, 11}, //  43
	{0x000000fa, 8},  //  44
	{0x00000016, 6},  //  45
	{0x00000017, 6},  //  46
	{0x00000018, 6},  //  47
	{0x00000000, 5},  //  48
	{0x00000001, 5},  //  49
	{0x00000002, 5},  //  50
	{0x00000019, 6},  //  51
	{0x0000001a, 6},  //  52
	{0x0000001b, 6},  //  53
	{0x0000001c, 6},  //  54
	{0x0000001d, 6},  //  55
	{0x0000001e, 6},  //  56
	{0x0000001f, 6},  //  57
	{0x0000005c, 7},  //  58
	{0x000000fb, 8},  //  59
	{0x00007ffc, 15}, //  60
	{0x00000020, 6},  //  61
	{0x00000ffb, 12}, //  62
	{0x000003fc, 10}, //  63
	{0x00001ffa, 13}, //  64
	{0x00000021, 6},  //  65
	{0x0000005d, 7},  //  66
	{0x0000005e, 7},  //  67
	{0x0000005f, 7},  //  68
	{0x00000060, 7},  //  69
	{0x00000061, 7},  //  70
	{0x00000062, 7},  //  71
	{0x00000063, 7},  //  72
	{0x00000064, 7},  //  73
	{0x00000065, 7},  //  74
	{0x00000066, 7},  //  75
	{0x00000067, 7},  //  76
	{0x00000068, 7},  //  77
	{0x00000069, 7},  //  78
	{0x0000006a, 7},  //  79
	{0x0000006b, 7},  //  80
	{0x0000006c, 7},  //  81
	{0x0000006d, 7},  //  82
	{0x0000006e, 7},  //  83
	{0x0000006f, 7},  //  84
	{0x00000070, 7},  //  85
	{0x00000071, 7},  //  86
	{0x00000072, 7},  //  87
	{0x000000fc, 8},  //  88
	{0x00000073, 7},  //  89
	{0x000000fd, 8},  //  90
	{0x00001ffb, 13}, //  91
	{0x0007fff0, 19}, //  92
	{0x00001ffc, 13}, //  93
	{0x00003ffc, 14}, //  94
	{0x00000022, 6},  //  95
	{0x00007ffd, 15}, //  96
	{0x00000003, 5},  //  97
	{0x00000023, 6},  //  98
	{0x00000004, 5},  //  99
	{0x00000024, 6},  // 100
	{0x00000005, 5},  // 101
	{0x00000025, 6},  // 102
	{0x00000026, 6},  // 103
	{0x00000027, 6},  // 104
	{0x00000006, 5},  // 105
	{0x00000074, 7},  // 106
	{0x00000075, 7},  // 107
	{0x00000028, 6},  // 108
	{0x00000029, 6},  // 109
	{0x0000002a, 6},  // 110
	{0x00000007, 5},  // 111
	{0x0000002b, 6},  // 112
	{0x00000076, 7},  // 113
	{0x0000002c, 6},  // 114
	{0x00000008, 5},  // 115
	{0x00000009, 5},  // 116
	{0x0000002d, 6},  // 117
	{0x00000077, 7},  // 118
	{0x00000078, 7},  // 119
	{0x00000079, 7},  // 120
	{0x0000007a, 7},  // 121
	{0x0000007b, 7},  // 122
	{0x00007ffe, 15}, // 123
	{0x000007fc, 11}, // 124
	{0x00003ffd, 14}, // 125
	{0x00001ffd, 13}, // 126
	{0x0ffffffc, 28}, // 127
	{0x000fffe6, 20}, // 128
	{0x003fffd2, 22}, // 129
	{0x000fffe7, 20}, // 130
	{0x000fffe8, 20}, // 131
	{0x003fffd3, 22}, // 132
	{0x003fffd4, 22}, // 133
	{0x003fffd5, 22}, // 134
	{0x007fffd9, 23}, // 135
	{0x003fffd6, 22}, // 136
	{0x007fffda, 23}, // 137
	{0x007fffdb, 23}, // 138
	{0x007fffdc, 23}, // 139
	{0x007fffdd, 23}, // 140
	{0x007fffde, 23}, // 141
	{0x00ffffeb, 24}, // 142
	{0x007fffdf, 23}, // 143
	{0x00ffffec, 24}, // 144
	{0x00ffffed, 24}, // 145
	{0x003fffd7, 22}, // 146
	{0x007fffe0, 23}, // 147
	{0x00ffffee, 24}, // 148
	{0x007fffe1, 23}, // 149
	{0x007fffe2, 23}, // 150
	{0x007fffe3, 23}, // 151
	{0x007fffe4, 23}, // 152
	{0x001fffdc, 21}, // 153
	{0x003fffd8, 22}, // 154
	{0x007fffe5, 23}, // 155
	{0x003fffd9, 22}, // 156
	{0x007fffe6, 23}, // 157
	{0x007fffe7, 23}, // 158
	{0x00ffffef, 24}, // 159
	{0x003fffda, 22}, // 160
	{0x001fffdd, 21}, // 161
	{0x000fffe9, 20}, // 162
	{0x003fffdb, 22}, // 163
	{0x003fffdc, 22}, // 164
	{0x007fffe8, 23}, // 165
	{0x007fffe9, 23}, // 166
	{0x001fffde, 21}, // 167
	{0x007fffea, 23}, // 168
	{0x003fffdd, 22}, // 169
	{0x003fffde, 22}, // 170
	{0x00fffff0, 24}, // 171
	{0x001fffdf, 21}, // 172
	{0x003fffdf, 22}, // 173
	{0x007fffeb, 23}, // 174
	{0x007fffec, 23}, // 175
	{0x001fffe0, 21}, // 176
	{0x001fffe1, 21}, // 177
	{0x003fffe0, 22}, // 178
	{0x001fffe2, 21}, // 179
	{0x007fffed, 23}, // 180
	{0x003fffe1, 22}, // 181
	{0x007fffee, 23}, // 182
	{0x007fffef, 23}, // 183
	{0x000fffea, 20}, // 184
	{0x003fffe2, 22}, // 185
	{0x003fffe3, 22}, // 186
	{0x003fffe4, 22}, // 187
	{0x007ffff0, 23}, // 188
	{0x003fffe5, 22}, // 189
	{0x003fffe6, 22}, // 190
	{0x007ffff1, 23}, // 191
	{0x03ffffe0, 26}, // 192
	{0x03ffffe1, 26}, // 193
	{0x000fffeb, 20}, // 194
	{0x0007fff1, 19}, // 195
	{0x003fffe7, 22}, // 196
	{0x007ffff2, 23}, // 197
	{0x003fffe8, 22}, // 198
	{0x01ffffec, 25}, // 199
	{0x03ffffe2, 26}, // 200
	{0x03ffffe3, 26}, // 201
	{0x03ffffe4, 26}, // 202
	{0x07ffffde, 27}, // 203
	{0x07ffffdf, 27}, // 204
	{0x03ffffe5, 26}, // 205
	{0x00fffff1, 24}, // 206
	{0x01ffffed, 25}, // 207
	{0x0007fff2, 19}, // 208
	{0x001fffe3, 21}, // 209
	{0x03ffffe6, 26}, // 210
	{0x07ffffe0, 27}, // 211
	{0x07ffffe1, 27}, // 212
	{0x03ffffe7, 26}, // 213
	{0x07ffffe2, 27}, // 214
	{0x00fffff2, 24}, // 215
	{0x001fffe4, 21}, // 216
	{0x001fffe5, 21}, // 217
	{0x03ffffe8, 26}, // 218
	{0x03ffffe9, 26}, // 219
	{0x0ffffffd, 28}, // 220
	{0x07ffffe3, 27}, // 221
	{0x07ffffe4, 27}, // 222
	{0x07ffffe5, 27}, // 223
	{0x000fffec, 20}, // 224
	{0x00fffff3, 24}, // 225
	{0x000fffed, 20}, // 226
	{0x001fffe6, 21}, // 227
	{0x003fffe9, 22}, // 228
	{0x001fffe7, 21}, // 229
	{0x001fffe8, 21}, // 230
	{0x007ffff3, 23}, // 231
	{0x003fffea, 22}, // 232
	{0x003fffeb, 22}, // 233
	{0x01ffffee, 25}, // 234
	{0x01ffffef, 25}, // 235
	{0x00fffff4, 24}, // 236
	{0x00fffff5, 24}, // 237
	{0x03ffffea, 26}, // 238
	{0x007ffff4, 23}, // 239
	{0x03ffffeb, 26}, // 240
	{0x07ffffe6, 27}, // 241
	{0x03ffffec, 26}, // 242
	{0x03ffffed, 26}, // 243
	{0x07ffffe7, 27}, // 244
	{0x07ffffe8, 27}, // 245
	{0x07ffffe9, 27}, // 246
	{0x07ffffea, 27}, // 247
	{0x07ffffeb, 27}, // 248
	{0x0ffffffe, 28}, // 249
	{0x07ffffec, 27}, // 250
	{0x07ffffed, 27}, // 251
	{0x07ffffee, 27}, // 252
	{0x07ffffef, 27}, // 253
	{0x07fffff0, 27}, // 254
	{0x03ffffee, 26}, // 255
	{0x3fffffff, 30}, // 256
}

// huffmanNode 是 Huffman 解码用的 Trie 节点。sym = -1 表示中间节点，
// 0..255 表示符号，256 表示 EOS（仅用于填充校验，不应作为符号出现）。
type huffmanNode struct {
	child [2]*huffmanNode
	sym   int16
}

var huffmanRoot = func() *huffmanNode {
	root := &huffmanNode{sym: -1}
	for sym, c := range huffmanCodes {
		node := root
		for i := int(c.length) - 1; i >= 0; i-- {
			bit := int((c.code >> uint(i)) & 1)
			if node.child[bit] == nil {
				node.child[bit] = &huffmanNode{sym: -1}
			}
			node = node.child[bit]
		}
		node.sym = int16(sym)
	}
	return root
}()

// HuffmanEncode 按 RFC 9204 / RFC 7541 Appendix B 对字节串做静态 Huffman 编码。
// 末尾不足 8 bit 的部分用 EOS 码的高位（全 1）补齐。
func HuffmanEncode(src []byte) []byte {
	out := make([]byte, 0, len(src))
	var acc uint64
	var nbits uint
	for _, b := range src {
		c := huffmanCodes[b]
		acc = acc<<uint(c.length) | uint64(c.code)
		nbits += uint(c.length)
		for nbits >= 8 {
			nbits -= 8
			out = append(out, byte(acc>>nbits))
		}
	}
	if nbits > 0 {
		pad := 8 - nbits
		out = append(out, byte(acc<<pad)|byte((1<<pad)-1))
	}
	return out
}

// HuffmanDecode 解码 RFC 9204 / RFC 7541 的静态 Huffman 字节串。
// 末尾允许不超过 7 bit 的填充，且填充位必须是 EOS 码的高位（全 1）。
func HuffmanDecode(src []byte) ([]byte, error) {
	out := make([]byte, 0, len(src))
	node := huffmanRoot
	var pending uint32 // 自上一个完整符号起累积的 bit
	var pendingBits uint
	for _, b := range src {
		for i := 7; i >= 0; i-- {
			bit := int((b >> uint(i)) & 1)
			node = node.child[bit]
			if node == nil {
				return nil, errors.New("http3proto: invalid Huffman code")
			}
			pending = pending<<1 | uint32(bit)
			pendingBits++
			if node.sym >= 0 {
				if node.sym == 256 {
					return nil, errors.New("http3proto: EOS symbol in Huffman string")
				}
				out = append(out, byte(node.sym))
				node = huffmanRoot
				pending, pendingBits = 0, 0
			}
		}
	}
	if node != huffmanRoot {
		if pendingBits > 7 {
			return nil, fmt.Errorf("http3proto: Huffman padding too long: %d bits", pendingBits)
		}
		if pending != (uint32(1)<<pendingBits)-1 {
			return nil, errors.New("http3proto: invalid Huffman padding")
		}
	}
	return out, nil
}
