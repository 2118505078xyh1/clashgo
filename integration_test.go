package main

import (
	"testing"

	"clashgo/internal/config"
	"clashgo/internal/kernel"
	"clashgo/internal/runtime"
)

// TestComplexProfileApply verifies the enhance pipeline + kernel can handle a
// realistic profile with multiple protocol types, groups, rules and DNS.
func TestComplexProfileApply(t *testing.T) {
	profile := []byte(`
port: 7890
socks-port: 7891
mixed-port: 7897
mode: rule
log-level: info
ipv6: false
allow-lan: false
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
proxies:
  - name: ss1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: test
  - name: vmess1
    type: vmess
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    cipher: auto
    tls: true
    servername: example.com
  - name: trojan1
    type: trojan
    server: example.com
    port: 443
    password: test
    sni: example.com
  - name: hysteria1
    type: hysteria
    server: example.com
    port: 443
    auth_str: test
    alpn: h3
    up: "30 Mbps"
    down: "200 Mbps"
proxy-groups:
  - name: PROXY
    type: select
    proxies: [ss1, vmess1, trojan1, hysteria1, DIRECT]
  - name: Auto
    type: url-test
    proxies: [ss1, vmess1, trojan1]
    url: https://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-KEYWORD,youtube,PROXY
  - IP-CIDR,1.1.1.1/32,PROXY
  - MATCH,DIRECT
`)
	s := config.DefaultSettings()
	s.MixedPort = 18897
	s.ExternalController = "127.0.0.1:19098"
	item := &config.PrfItem{Name: "complex", File: "complex.yaml"}
	generated, err := runtime.Generate(profile, s, item, nil, t.TempDir()+"/runtime.yaml")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := kernel.ParseOnly(generated); err != nil {
		t.Fatalf("kernel rejected generated config: %v\n%s", err, generated)
	}
}
