package quicproto

// QUIC frame encoding/decoding (RFC 9000 §12, §19) and reassembly buffers.

import (
	"errors"
	"io"
)

// QUIC frame types used by this stack.
const (
	framePadding = 0x00
	frameACK     = 0x02
	frameACKECN  = 0x03
	frameCrypto  = 0x06
	frameStream  = 0x08 // plus FIN/LEN/OFF bits
	// RFC 9221 §4: DATAGRAM type = 0x30 | LEN；LEN=0x01 表示带 Length 字段。
	frameDatagramNoLen   = 0x30 // 无 Length，数据延伸到包尾
	frameDatagram        = 0x31 // 带 Length 字段
	frameConnectionClose = 0x1c

	streamFlagFIN = 0x01
	streamFlagLEN = 0x02
	streamFlagOFF = 0x04
)

// readVarint decodes a QUIC variable-length integer (RFC 9000 §1.1).
func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length, nil
}

// ---------------------------------------------------------------------------
// Frame encoders
// ---------------------------------------------------------------------------

func appendCryptoFrame(b []byte, offset uint64, data []byte) []byte {
	b = append(b, frameCrypto)
	b = appendVarint(b, offset)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendPaddingFrames(b []byte, n int) []byte {
	for i := 0; i < n; i++ {
		b = append(b, framePadding)
	}
	return b
}

type ackRange struct {
	gap    uint64 // number of packet numbers omitted since previous range
	length uint64 // number of consecutive packet numbers in this range
}

func appendACKFrame(b []byte, largest uint64, delay uint64, ranges []ackRange) []byte {
	b = append(b, frameACK)
	b = appendVarint(b, largest)
	b = appendVarint(b, delay)
	// RFC 9000 §19.3.1: ACK Range Count 是「额外的」range 数量，
	// 不含 First ACK Range。至少一个 range 时必须写 First ACK Range；
	// ranges 为空时仍需写 First ACK Range=0（表示 largest 未被确认）。
	if len(ranges) == 0 {
		b = appendVarint(b, 0) // ACK Range Count = 0
		b = appendVarint(b, 0) // First ACK Range = 0（gap 隐含为 0）
		return b
	}
	b = appendVarint(b, uint64(len(ranges)-1)) // 额外 range 数
	// ackRange 的 gap/length 已是 RFC 线格式语义：
	// First ACK Range = largest - smallest；Gap = 前段 smallest - 本段 largest - 2。
	b = appendVarint(b, ranges[0].length)
	for i := 1; i < len(ranges); i++ {
		b = appendVarint(b, ranges[i].gap)
		b = appendVarint(b, ranges[i].length)
	}
	return b
}

// appendStreamFrame builds a STREAM frame.  The stream ID is always included
// (OFF bit set) so that streams other than 0 can be addressed.
func appendStreamFrame(b []byte, streamID, offset uint64, data []byte, fin bool) []byte {
	typ := byte(frameStream | streamFlagOFF | streamFlagLEN)
	if fin {
		typ |= streamFlagFIN
	}
	b = append(b, typ)
	b = appendVarint(b, streamID)
	b = appendVarint(b, offset)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

// appendDatagramFrame builds a DATAGRAM frame with an explicit length field
// (frame type 0x30, RFC 9000 §19.4). DATAGRAMs are unreliable and are never
// retransmitted or flow controlled.
func appendDatagramFrame(b []byte, data []byte) []byte {
	b = append(b, frameDatagram)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendConnectionCloseFrame(b []byte, code uint64, reason string) []byte {
	b = append(b, frameConnectionClose)
	b = appendVarint(b, code)
	b = appendVarint(b, uint64(len(reason)))
	return append(b, reason...)
}

// ---------------------------------------------------------------------------
// Frame decoder
// ---------------------------------------------------------------------------

type cryptoFrameData struct {
	offset uint64
	data   []byte
}

type streamFrameData struct {
	streamID uint64
	offset   uint64
	data     []byte
	fin      bool
}

type ackFrameData struct {
	largest uint64
	delay   uint64
	ranges  []ackRange
	// packets is the expanded list of acknowledged packet numbers.
	packets []uint64
}

type parsedFrame struct {
	typ      byte
	crypto   *cryptoFrameData
	stream   *streamFrameData
	ack      *ackFrameData
	datagram []byte // payload of a 0x30 DATAGRAM frame
	code     uint64
	reason   string
}

func parseFrames(data []byte) ([]parsedFrame, error) {
	var out []parsedFrame
	for len(data) > 0 {
		typ := data[0]
		data = data[1:]
		switch {
		case typ == framePadding:
			out = append(out, parsedFrame{typ: typ})
			continue
		case typ == frameACK || typ == frameACKECN:
			largest, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			delay, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			count, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			af := &ackFrameData{largest: largest, delay: delay}
			// RFC 9000 §19.3.1：count 是「额外」range 数；First ACK Range
			// 无条件存在（First Range 的 gap 隐含为 0）。
			firstLen, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			// prevSmallest 是上一段的最小包号；本段 largest = prevSmallest - gap - 2。
			prevSmallest := largest
			// addRange 接收 RFC 线格式值：gap=前段smallest-本段largest-2，
			// length=largest-smallest。确认包数 = length+1。
			addRange := func(gap, length uint64, first bool) error {
				var currLargest uint64
				if first {
					currLargest = largest
				} else {
					if gap+2 > prevSmallest {
						return errors.New("quicproto: invalid ACK range gap")
					}
					currLargest = prevSmallest - gap - 2
				}
				if length > currLargest {
					length = currLargest // smallest 不能小于 0
				}
				currSmallest := currLargest - length
				for pn := currLargest; ; pn-- {
					af.packets = append(af.packets, pn)
					if pn == currSmallest || pn == 0 {
						break
					}
				}
				af.ranges = append(af.ranges, ackRange{gap: gap, length: length})
				prevSmallest = currSmallest
				return nil
			}
			if err := addRange(0, firstLen, true); err != nil {
				return nil, err
			}
			for i := uint64(0); i < count; i++ {
				gap, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				data = data[n:]
				length, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				data = data[n:]
				if err := addRange(gap, length, false); err != nil {
					return nil, err
				}
			}
			out = append(out, parsedFrame{typ: frameACK, ack: af})
		case typ == frameCrypto:
			offset, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			length, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return nil, io.ErrUnexpectedEOF
			}
			out = append(out, parsedFrame{typ: typ, crypto: &cryptoFrameData{offset: offset, data: data[:length]}})
			data = data[length:]
		case typ&0x08 == 0x08 && typ&0x10 == 0: // STREAM frame
			sf := &streamFrameData{fin: typ&streamFlagFIN != 0}
			lengthPresent := typ&streamFlagLEN != 0
			// STREAM type 0x08 means stream 0 with no stream ID field.
			if typ != frameStream {
				v, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				sf.streamID = v
				data = data[n:]
			}
			if typ&streamFlagOFF != 0 {
				v, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				sf.offset = v
				data = data[n:]
			}
			var length uint64
			if lengthPresent {
				v, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				length = v
				data = data[n:]
			} else {
				length = uint64(len(data))
			}
			if uint64(len(data)) < length {
				return nil, io.ErrUnexpectedEOF
			}
			sf.data = data[:length]
			data = data[length:]
			out = append(out, parsedFrame{typ: frameStream, stream: sf})
		case typ == frameDatagram:
			// DATAGRAM with length: 0x30 + varint(length) + data (§19.4).
			length, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return nil, io.ErrUnexpectedEOF
			}
			out = append(out, parsedFrame{typ: typ, datagram: append([]byte(nil), data[:length]...)})
			data = data[length:]
		case typ == frameDatagramNoLen:
			// DATAGRAM without length: all remaining bytes are the payload.
			out = append(out, parsedFrame{typ: typ, datagram: append([]byte(nil), data...)})
			data = nil
		case typ == 0x01 || typ == 0x1e:
			// PING and HANDSHAKE_DONE carry no fields.
			out = append(out, parsedFrame{typ: typ})
		case typ == 0x10 || typ == 0x12 || typ == 0x13 || typ == 0x14 || typ == 0x16 || typ == 0x17 || typ == 0x19:
			// MAX_DATA, MAX_STREAMS, DATA_BLOCKED, STREAMS_BLOCKED and
			// RETIRE_CONNECTION_ID each carry a single varint.
			if _, _, err := readVarint(data); err != nil {
				return nil, err
			}
			_, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			out = append(out, parsedFrame{typ: typ})
			data = data[n:]
		case typ == 0x11 || typ == 0x15:
			// MAX_STREAM_DATA and STREAM_DATA_BLOCKED: two varints.
			for i := 0; i < 2; i++ {
				_, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				data = data[n:]
			}
			out = append(out, parsedFrame{typ: typ})
		case typ == 0x1a || typ == 0x1b:
			// PATH_CHALLENGE and PATH_RESPONSE: 8 fixed bytes.
			if len(data) < 8 {
				return nil, io.ErrUnexpectedEOF
			}
			out = append(out, parsedFrame{typ: typ})
			data = data[8:]
		case typ == 0x07 || typ == 0x18:
			// NEW_TOKEN: length-prefixed token.
			// NEW_CONNECTION_ID: seq, retire, CID length + CID, 16-byte token.
			if typ == 0x07 {
				length, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				data = data[n:]
				if uint64(len(data)) < length {
					return nil, io.ErrUnexpectedEOF
				}
				data = data[length:]
			} else {
				for i := 0; i < 2; i++ { // sequence number, retire prior to
					_, n, err := readVarint(data)
					if err != nil {
						return nil, err
					}
					data = data[n:]
				}
				cidLen, n, err := readVarint(data)
				if err != nil {
					return nil, err
				}
				data = data[n:]
				if uint64(len(data)) < cidLen+16 {
					return nil, io.ErrUnexpectedEOF
				}
				data = data[cidLen+16:]
			}
			out = append(out, parsedFrame{typ: typ})
		case typ == frameConnectionClose || typ == 0x1d:
			code, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			length, n, err := readVarint(data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			if uint64(len(data)) < length {
				return nil, io.ErrUnexpectedEOF
			}
			out = append(out, parsedFrame{typ: typ, code: code, reason: string(data[:length])})
			data = data[length:]
		default:
			// Unknown frames cannot be skipped without knowing their length;
			// the remainder of this packet is discarded rather than
			// mis-interpreting frames that follow it.
			return nil, nil
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Reassembly buffers
// ---------------------------------------------------------------------------

// cryptoBuffer reassembles CRYPTO frames into a contiguous byte stream for
// one encryption level.
type cryptoBuffer struct {
	buf        []byte
	received   []bool
	readOffset uint64
}

func (cb *cryptoBuffer) add(offset uint64, data []byte) []byte {
	end := offset + uint64(len(data))
	if end > uint64(len(cb.buf)) {
		cb.buf = append(cb.buf, make([]byte, end-uint64(len(cb.buf)))...)
		cb.received = append(cb.received, make([]bool, end-uint64(len(cb.received)))...)
	}
	for i, b := range data {
		idx := offset + uint64(i)
		if !cb.received[idx] {
			cb.received[idx] = true
			cb.buf[idx] = b
		}
	}
	var contiguous []byte
	for cb.readOffset < uint64(len(cb.buf)) && cb.received[cb.readOffset] {
		contiguous = append(contiguous, cb.buf[cb.readOffset])
		cb.readOffset++
	}
	return contiguous
}

// streamReassembler reorders STREAM frames for a single stream.
type streamReassembler struct {
	buf        []byte
	received   []bool
	readOffset uint64
	finOffset  uint64
	fin        bool
}

func (sr *streamReassembler) add(offset uint64, data []byte, fin bool) []byte {
	end := offset + uint64(len(data))
	if end > uint64(len(sr.buf)) {
		sr.buf = append(sr.buf, make([]byte, end-uint64(len(sr.buf)))...)
		sr.received = append(sr.received, make([]bool, end-uint64(len(sr.received)))...)
	}
	for i, b := range data {
		idx := offset + uint64(i)
		if !sr.received[idx] {
			sr.received[idx] = true
			sr.buf[idx] = b
		}
	}
	if fin && !sr.fin {
		sr.fin = true
		sr.finOffset = end
	}
	var contiguous []byte
	for sr.readOffset < uint64(len(sr.buf)) && sr.received[sr.readOffset] {
		contiguous = append(contiguous, sr.buf[sr.readOffset])
		sr.readOffset++
	}
	return contiguous
}
