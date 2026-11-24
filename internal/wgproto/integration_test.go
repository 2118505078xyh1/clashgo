package wgproto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestTunnelEndToEnd 用一个本地 UDP "响应方" 完整跑通握手 + 数据传输。
func TestTunnelEndToEnd(t *testing.T) {
	curve := ecdh.X25519()
	initStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	respStatic, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	type session struct {
		sendKey, recvKey [32]byte
	}
	sessions := make(chan session, 1)
	errCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 65535)
		var s session
		for {
			n, addr, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			if len(msg) < 4 {
				continue
			}
			switch binary.LittleEndian.Uint32(msg[0:4]) {
			case messageInitiationType:
				resp, sendKey, recvKey := responderHandshake(t, msg, respStatic, initStatic.PublicKey().Bytes())
				s = session{sendKey: sendKey, recvKey: recvKey}
				sessions <- s
				if _, err := udp.WriteToUDP(resp, addr); err != nil {
					errCh <- err
					return
				}
			case messageTransportType:
				if len(msg) < transportHeaderSize+aeadTagSize {
					continue
				}
				counter := binary.LittleEndian.Uint64(msg[8:16])
				recvAEAD, _ := newChaCha20Poly1305(s.recvKey[:])
				nonce := makeNonce(counter)
				plain, err := recvAEAD.Open(nil, nonce[:], msg[transportHeaderSize:], nil)
				if err != nil {
					errCh <- err
					return
				}
				// 回显：用响应方的 send key 加密，counter 减 1 表示响应方向
				sendAEAD, _ := newChaCha20Poly1305(s.sendKey[:])
				respNonce := makeNonce(7)
				sealed := sendAEAD.Seal(nil, respNonce[:], plain, nil)
				out := make([]byte, transportHeaderSize+len(sealed))
				binary.LittleEndian.PutUint32(out[0:4], messageTransportType)
				binary.LittleEndian.PutUint32(out[4:8], binary.LittleEndian.Uint32(msg[4:8]))
				binary.LittleEndian.PutUint64(out[8:16], 7)
				copy(out[transportHeaderSize:], sealed)
				if _, err := udp.WriteToUDP(out, addr); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	cfg := Config{
		PrivateKey:    base64.StdEncoding.EncodeToString(initStatic.Bytes()),
		PeerPublicKey: base64.StdEncoding.EncodeToString(respStatic.PublicKey().Bytes()),
		Endpoint:      udp.LocalAddr().String(),
		AllowedIPs:    []string{"10.0.0.0/24", "fd00::/8"},
		Keepalive:     0,
	}
	tun, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	if err := tun.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sessions:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("no handshake session")
	}

	if len(tun.AllowedIPs()) != 2 {
		t.Fatalf("allowed IPs = %d", len(tun.AllowedIPs()))
	}

	payload := []byte("inner IP packet 0x45 0x00 ...")
	if _, err := tun.WriteTo(payload, tun.RemoteAddr()); err != nil {
		t.Fatal(err)
	}
	if err := tun.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2048)
	n, _, err := tun.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Errorf("echo = %q, want %q", got[:n], payload)
	}
}
