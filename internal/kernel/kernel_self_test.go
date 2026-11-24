package kernel

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSelfKernelStartsListenerAndAPI(t *testing.T) {
	mixed := freePort(t)
	apiPort := freePort(t)
	cfg := fmt.Sprintf(`
mixed-port: %d
external-controller: 127.0.0.1:%d
secret: test
proxies:
  - name: SS1
    type: ss
    server: 127.0.0.1
    port: 12345
    cipher: aes-256-gcm
    password: pwd
proxy-groups:
  - name: PROXY
    type: select
    proxies: [SS1, DIRECT]
rules:
  - MATCH,PROXY
`, mixed, apiPort)

	k := New()
	defer k.Stop()
	if err := k.ApplyWithController([]byte(cfg), fmt.Sprintf("127.0.0.1:%d", apiPort), "test"); err != nil {
		t.Fatal(err)
	}
	if !k.Started() {
		t.Fatal("kernel not started")
	}

	// API：GET /version（带 Bearer）。
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/version", apiPort), nil)
	req.Header.Set("Authorization", "Bearer test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("API status = %d, body=%s", resp.StatusCode, body)
	}
	if string(body) == "" {
		t.Fatal("empty API response")
	}

	// mixed 监听器：SOCKS5 方法协商应回 {5,0}。
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", mixed))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 reply = %v, %v", reply, err)
	}
}
