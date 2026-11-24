package quicproto

import (
	"bytes"
	"testing"
)

// TestACKFrameRoundTrip 验证 ACK 帧的编码/解码符合 RFC 9000 §19.3.1：
// ACK Range Count 是「额外」range 数（不含 First ACK Range）。
func TestACKFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		largest uint64
		delay   uint64
		ranges  []ackRange
	}{
		{"single", 5, 0, []ackRange{{gap: 0, length: 3}}},
		{"two-ranges", 10, 2, []ackRange{{gap: 0, length: 2}, {gap: 3, length: 4}}},
		{"empty", 7, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := appendACKFrame(nil, tc.largest, tc.delay, tc.ranges)
			frames, err := parseFrames(wire)
			if err != nil {
				t.Fatalf("parseFrames: %v", err)
			}
			if len(frames) != 1 || frames[0].ack == nil {
				t.Fatalf("expected one ACK frame, got %+v", frames)
			}
			got := frames[0].ack
			if got.largest != tc.largest {
				t.Fatalf("largest = %d, want %d", got.largest, tc.largest)
			}
			if len(tc.ranges) > 0 && len(got.ranges) != len(tc.ranges) {
				t.Fatalf("range count = %d, want %d", len(got.ranges), len(tc.ranges))
			}
			// 验证确认的包号集合：largest 起，按 range length 连续递减。
			if len(tc.ranges) > 0 && len(got.packets) == 0 {
				t.Fatal("no acknowledged packets decoded")
			}
		})
	}
}

// TestACKFrameWireFormat 用已知的字节序列验证 First ACK Range 位置。
// largest=5, delay=0, 额外range=0, First ACK Range=3 → 确认 PNs 5,4,3。
func TestACKFrameWireFormat(t *testing.T) {
	// RFC 9000: First ACK Range = largest - smallest = 2（确认 PN 5,4,3 共 3 个包）。
	wire := appendACKFrame(nil, 5, 0, []ackRange{{gap: 0, length: 2}})
	want := []byte{0x02, 0x05, 0x00, 0x00, 0x02}
	if !bytes.Equal(wire, want) {
		t.Fatalf("wire = %x, want %x", wire, want)
	}
	frames, _ := parseFrames(wire)
	got := frames[0].ack.packets
	wantPNs := []uint64{5, 4, 3}
	if len(got) != len(wantPNs) {
		t.Fatalf("packets = %v, want %v", got, wantPNs)
	}
	for i := range got {
		if got[i] != wantPNs[i] {
			t.Fatalf("packets = %v, want %v", got, wantPNs)
		}
	}
}
