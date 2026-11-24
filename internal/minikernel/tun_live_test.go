package minikernel

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// TestLiveTUN 在具备管理员权限 + TAP-Windows 适配器的环境里做实机验证。
// 设置 CLASHGO_TUN_LIVE=1 后运行：
//
//	CLASHGO_TUN_LIVE=1 go test ./internal/minikernel/ -run TestLiveTUN -v
//
// 它会探测 TAP、打开并配置适配器、注入一个 ICMP echo 并尝试读回响应。
// 前置条件不满足时自动跳过（见 VERIFY.md）。
func TestLiveTUN(t *testing.T) {
	if os.Getenv("CLASHGO_TUN_LIVE") != "1" {
		t.Skip("set CLASHGO_TUN_LIVE=1 (admin + TAP-Windows required)")
	}
	name, err := ProbeTAP()
	if err != nil {
		t.Skipf("TAP prerequisite not met: %v", err)
	}
	t.Logf("TAP adapter: %s", name)

	dev, err := openTAP("")
	if err != nil {
		t.Fatalf("openTAP: %v", err)
	}
	defer dev.Close()

	gw := [4]byte{198, 18, 0, 1}
	mask := [4]byte{255, 255, 0, 0}
	if err := dev.configure(gw, mask, gw, 1500); err != nil {
		t.Fatalf("configure TAP: %v", err)
	}

	// 构造 ICMP echo request：src=198.18.0.2 → dst=198.18.0.1（TAP 网关）。
	pkt := buildICMPEcho([4]byte{198, 18, 0, 2}, gw)
	if _, err := dev.Write(pkt); err != nil {
		t.Fatalf("write ICMP echo to TAP: %v", err)
	}

	// 从适配器读回数据（OS 对网关地址的 echo reply），最多等 5 秒。
	got := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		n, err := dev.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		got <- append([]byte(nil), buf[:n]...)
	}()

	select {
	case wire := <-got:
		if len(wire) < 20 {
			t.Fatalf("short packet from TAP: %d bytes", len(wire))
		}
		if wire[9] != 1 { // IPv4 proto = ICMP
			t.Logf("received non-ICMP packet from TAP (proto=%d); adapter I/O works", wire[9])
		} else {
			t.Logf("received ICMP reply from TAP: %d bytes", len(wire))
		}
	case err := <-errCh:
		t.Fatalf("read TAP: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no packet from TAP within 5s (check firewall / adapter state)")
	}
}

// buildICMPEcho 构造一个最小的 IPv4 + ICMP echo request 包。
func buildICMPEcho(src, dst [4]byte) []byte {
	const icmpLen = 8 + 4
	pkt := make([]byte, 20+icmpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	pkt[20] = 8                               // echo request
	binary.BigEndian.PutUint16(pkt[24:26], 1) // id
	binary.BigEndian.PutUint16(pkt[26:28], 1) // seq
	copy(pkt[28:], "ping")
	binary.BigEndian.PutUint16(pkt[22:24], ^internetChecksum(pkt[20:]))
	binary.BigEndian.PutUint16(pkt[10:12], ^internetChecksum(pkt[:20]))
	return pkt
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}
