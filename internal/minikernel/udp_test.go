package minikernel

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestSOCKS5UDPAssociate(t *testing.T) {
	echo := startUDPEcho(t)
	k := NewKernel()
	l, err := Start(k, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// 1. TCP 控制连接：方法协商 + UDP ASSOCIATE。
	ctl, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	ctl.Write([]byte{0x05, 0x01, 0x00})
	if _, err := io.ReadFull(ctl, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	ctl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // CMD=3 UDP ASSOCIATE
	rep := make([]byte, 10)
	if _, err := io.ReadFull(ctl, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("associate reply = %v, %v", rep, err)
	}

	// 2. 向 mixed 端口的 UDP 端发送 SOCKS5 UDP 包。
	udpAddr, err := net.ResolveUDPAddr("udp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	host, portStr, _ := net.SplitHostPort(echo)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	ip := net.ParseIP(host).To4()
	pkt := []byte{0, 0, 0, 0x01}
	pkt = append(pkt, ip...)
	pvar := make([]byte, 2)
	binary.BigEndian.PutUint16(pvar, uint16(port))
	pkt = append(pkt, pvar...)
	pkt = append(pkt, []byte("udp-echo-test")...)

	if _, err := client.WriteTo(pkt, udpAddr); err != nil {
		t.Fatal(err)
	}

	// 3. 收回应包（SOCKS5 UDP 格式）。
	buf := make([]byte, 4096)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("short reply %d", n)
	}
	if string(buf[n-len("udp-echo-test"):n]) != "udp-echo-test" {
		t.Fatalf("payload = %q", buf[:n])
	}
}
