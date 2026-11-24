package speedtest

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPPing(t *testing.T) {
	// Start a local TCP listener to ping.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ms := TCPPing(context.Background(), "127.0.0.1", port, time.Second)
	if ms < 0 {
		t.Fatal("TCP ping to local listener failed")
	}
	if ms > 1000 {
		t.Errorf("TCP ping too high: %dms", ms)
	}
}

func TestTCPPingFail(t *testing.T) {
	ms := TCPPing(context.Background(), "127.0.0.1", "1", 200*time.Millisecond)
	if ms != -1 {
		t.Errorf("expected -1 for closed port, got %d", ms)
	}
}
