package profile

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestConvertShareLinksVMessAndVLESS(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"测试节点","add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com"}`
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	vless := "vless://11111111-2222-3333-4444-555555555555@example.org:443?encryption=none&security=tls&sni=example.org&type=tcp&flow=xtls-rprx-vision#VLESS%20Node"
	raw := []byte(strings.Join([]string{vmess, vless}, "\n"))

	out, err := ConvertShareLinks(raw)
	if err != nil {
		t.Fatalf("ConvertShareLinks: %v", err)
	}
	if err := ValidateConfig(out); err != nil {
		t.Fatalf("converted config invalid: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{"type: vmess", "type: vless", "example.com", "example.org", "VLESS Node", "MATCH,PROXY"} {
		if !strings.Contains(s, want) {
			t.Errorf("converted config missing %q:\n%s", want, s)
		}
	}
}
