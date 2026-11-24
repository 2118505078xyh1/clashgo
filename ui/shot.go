package ui

import (
	"time"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
	"clashgo/internal/dnsq"
)

// NewAppForShot builds a fresh App whose router starts at the given page,
// for headless screenshot rendering. It skips network polling since no
// window is attached.
func NewAppForShot(startPath string) (*App, error) {
	a, err := newAppWithOptions(true) // skip kernel start — screenshots need no core
	if err != nil {
		return nil, err
	}
	a.router = ui.NewRouter(startPath)
	fillDemoData(a)
	return a, nil
}

// fillDemoData injects representative data so every page renders with
// realistic content in screenshots.
func fillDemoData(a *App) {
	nodesJP := []string{"🇯🇵 东京 01", "🇯🇵 东京 02", "🇭🇰 香港 01", "🇺🇸 洛杉矶 01", "🇸🇬 新加坡 01"}
	nodesHK := []string{"🇭🇰 香港 01", "🇭🇰 香港 02", "🇯🇵 东京 01", "🇺🇸 洛杉矶 01"}

	a.Version = map[string]any{"meta": true, "version": "1.19.34"}
	a.Proxies = map[string]config.ProxyView{
		"PROXY":     {Name: "PROXY", Type: "Selector", Now: "🇭🇰 香港 01", All: nodesJP, Group: true, UDP: true},
		"Auto":      {Name: "Auto", Type: "URLTest", Now: "🇯🇵 东京 01", All: nodesJP, Group: true, UDP: true},
		"🇭🇰 香港 01":  {Name: "🇭🇰 香港 01", Type: "Hysteria2", UDP: true, History: []config.DelayHistory{{Time: time.Now().Format("15:04:05"), Delay: 45}}},
		"🇯🇵 东京 01":  {Name: "🇯🇵 东京 01", Type: "VLESS", UDP: true, History: []config.DelayHistory{{Time: time.Now().Format("15:04:05"), Delay: 88}}},
		"🇺🇸 洛杉矶 01": {Name: "🇺🇸 洛杉矶 01", Type: "Trojan", UDP: true, History: []config.DelayHistory{{Time: time.Now().Format("15:04:05"), Delay: 210}}},
		"DIRECT":    {Name: "DIRECT", Type: "Direct", UDP: true},
	}
	nodes := []string{"🇭🇰 香港 01", "🇯🇵 东京 01", "🇺🇸 洛杉矶 01", "🇸🇬 新加坡 01", "DIRECT"}
	for _, n := range nodes {
		a.Delays[n] = map[string]int{"🇭🇰 香港 01": 45, "🇯🇵 东京 01": 88, "🇺🇸 洛杉矶 01": 210, "🇸🇬 新加坡 01": 130, "DIRECT": 0}[n]
	}
	_ = nodesHK

	a.Rules = []map[string]any{
		{"type": "DOMAIN-SUFFIX", "payload": "google.com", "proxy": "PROXY"},
		{"type": "DOMAIN-KEYWORD", "payload": "youtube", "proxy": "PROXY"},
		{"type": "DOMAIN-SUFFIX", "payload": "github.com", "proxy": "PROXY"},
		{"type": "IP-CIDR", "payload": "1.1.1.1/32", "proxy": "PROXY"},
		{"type": "GEOIP", "payload": "US", "proxy": "PROXY"},
		{"type": "GEOSITE", "payload": "geolocation-!cn", "proxy": "PROXY"},
		{"type": "PROCESS-NAME", "payload": "chrome.exe", "proxy": "DIRECT"},
		{"type": "MATCH", "payload": "", "proxy": "DIRECT"},
	}

	now := time.Now().Format("15:04:05")
	a.Connections = []config.ConnectionView{
		{ID: "1", Start: now, Host: "www.google.com", Full: "tcp://www.google.com:443", Network: "tcp", Type: "HTTP/1.1", Rule: "DOMAIN-SUFFIX", RulePayload: "google.com", Chain: []string{"PROXY", "🇭🇰 香港 01"}, Upload: 15234, Download: 892341, SourceIP: "127.0.0.1"},
		{ID: "2", Start: now, Host: "api.openai.com", Full: "tcp://api.openai.com:443", Network: "tcp", Type: "HTTP/2", Rule: "DOMAIN-SUFFIX", RulePayload: "openai.com", Chain: []string{"PROXY", "🇯🇵 东京 01"}, Upload: 8234, Download: 241341, SourceIP: "127.0.0.1"},
		{ID: "3", Start: now, Host: "github.com", Full: "tcp://github.com:443", Network: "tcp", Type: "HTTP/1.1", Rule: "DOMAIN-SUFFIX", RulePayload: "github.com", Chain: []string{"PROXY", "🇺🇸 洛杉矶 01"}, Upload: 3412, Download: 128934, SourceIP: "127.0.0.1"},
		{ID: "4", Start: now, Host: "dns.google", Full: "udp://dns.google:53", Network: "udp", Type: "DNS", Rule: "MATCH", Chain: []string{"DIRECT"}, Upload: 512, Download: 1024, SourceIP: "127.0.0.1"},
	}

	a.Logs = []config.LogView{
		{Type: "info", Time: now, Payload: "use proxy PROXY[香港 01] to dial tcp www.google.com:443"},
		{Type: "debug", Time: now, Payload: "[DNS] resolve www.google.com A from 223.5.5.5:53"},
		{Type: "debug", Time: now, Payload: "[DNS] www.google.com --> 142.250.72.100 from 223.5.5.5:53"},
		{Type: "debug", Time: now, Payload: "[DNS] cache hit api.openai.com --> 104.18.32.47"},
		{Type: "warning", Time: now, Payload: "[DNS] resolve api.openai.com error: context deadline exceeded"},
		{Type: "info", Time: now, Payload: "TCP connection established from 127.0.0.1:52341"},
		{Type: "error", Time: now, Payload: "dial tcp 1.2.3.4:443: i/o timeout"},
		{Type: "info", Time: now, Payload: "inbound connection to mixed-port 7897"},
	}
	a.DNSRecords = []dnsq.Record{
		{Time: now, Type: "resolve", Domain: "www.google.com", Answer: "A ?", Server: "223.5.5.5:53"},
		{Time: now, Type: "resolve", Domain: "www.google.com", Answer: "142.250.72.100", Server: "223.5.5.5:53"},
		{Time: now, Type: "hit", Domain: "api.openai.com", Answer: "104.18.32.47"},
		{Time: now, Type: "error", Domain: "api.openai.com", Answer: "resolve error: context deadline exceeded"},
		{Time: now, Type: "resolve", Domain: "github.com", Answer: "140.82.112.3", Server: "1.1.1.1:53"},
	}
	a.Requests = append(a.Requests, a.Connections...)
	a.ActiveReqIDs = map[string]int{}
	for i, r := range a.Requests {
		a.ActiveReqIDs[r.ID] = i
	}

	a.DownRate = 2 * 1024 * 1024
	a.UpRate = 256 * 1024
	a.Down = 892341
	a.Up = 15234
	for i := 0; i < 60; i++ {
		a.downHistory = append(a.downHistory, 300000+float64((i*7919)%500000))
		a.upHistory = append(a.upHistory, 100000+float64((i*3571)%180000))
	}
}
