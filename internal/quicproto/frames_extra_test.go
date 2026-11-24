package quicproto

import (
	"bytes"
	"testing"
)

func TestDatagramFrameRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("a"), bytes.Repeat([]byte("d"), 300)} {
		frame := appendDatagramFrame(nil, payload)
		if frame[0] != frameDatagram {
			t.Fatalf("frame type = %02x, want 30", frame[0])
		}
		frames, err := parseFrames(frame)
		if err != nil {
			t.Fatal(err)
		}
		if len(frames) != 1 || !bytes.Equal(frames[0].datagram, payload) {
			t.Fatalf("round trip failed for %d-byte payload: %+v", len(payload), frames)
		}
	}

	// DATAGRAM frames can be coalesced after other frames.
	b := appendStreamFrame(nil, 0, 0, []byte("stream"), true)
	b = appendDatagramFrame(b, []byte("dg"))
	frames, err := parseFrames(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || frames[0].stream == nil || !bytes.Equal(frames[1].datagram, []byte("dg")) {
		t.Fatalf("coalesced frames: %+v", frames)
	}

	// Length-less DATAGRAM (0x31): the remainder of the packet is the data.
	frames, err = parseFrames([]byte{frameDatagramNoLen, 'h', 'i'})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0].datagram, []byte("hi")) {
		t.Fatalf("0x31 frame: %+v", frames)
	}
}

// RFC 9001 Appendix A.4: Retry packet and its integrity tag.
func TestRetryIntegrityVector(t *testing.T) {
	pkt := hx(t, "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
	odcid := hx(t, "8394c8f03e515708")
	if !verifyRetryIntegrity(pkt, odcid) {
		t.Fatal("RFC 9001 A.4 Retry integrity tag did not verify")
	}
	// Corrupting either the token or the ODCID must fail.
	bad := append([]byte(nil), pkt...)
	bad[20] ^= 0xff
	if verifyRetryIntegrity(bad, odcid) {
		t.Fatal("corrupted Retry was accepted")
	}
	if verifyRetryIntegrity(pkt, hx(t, "0011223344556677")) {
		t.Fatal("Retry with wrong ODCID was accepted")
	}
}
