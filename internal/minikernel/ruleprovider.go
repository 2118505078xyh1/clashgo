package minikernel

import (
	"net/http"
	"os"
	"strings"
	"time"

	"clashgo/internal/yaml"
)

// RuleProviderConfig 是 rule-provider 配置。
type RuleProviderConfig struct {
	Type     string   `yaml:"type"`
	Path     string   `yaml:"path"`
	URL      string   `yaml:"url"`
	Behavior string   `yaml:"behavior"` // domain / ipcidr / classical
	Payload  []string `yaml:"payload"`
}

// loadRuleProviders 加载所有 rule-provider，填充全局 ruleSets 注册表。
func loadRuleProviders(providers map[string]RuleProviderConfig) {
	for name, cfg := range providers {
		lines := cfg.Payload // 内联 payload
		if len(lines) == 0 && cfg.Path != "" {
			if data, err := os.ReadFile(cfg.Path); err == nil {
				lines = extractPayload(data)
			}
		}
		if len(lines) == 0 && cfg.URL != "" {
			lines = fetchPayload(cfg.URL)
		}
		if len(lines) == 0 {
			continue
		}
		holder := &ruleSetHolder{domainRules: []Rule{}, ipRules: []Rule{}}
		for _, line := range lines {
			r, err := ParseRule(strings.TrimSpace(line))
			if err != nil {
				continue
			}
			switch r.Type() {
			case "IP-CIDR", "IP-CIDR6", "GEOIP":
				holder.ipRules = append(holder.ipRules, r)
			default:
				holder.domainRules = append(holder.domainRules, r)
			}
		}
		ruleSets[strings.ToLower(name)] = holder
	}
}

// extractPayload 从规则集 YAML 里提取 payload 列表。
func extractPayload(data []byte) []string {
	var m struct {
		Payload []string `yaml:"payload"`
	}
	if yaml.Unmarshal(data, &m) == nil && len(m.Payload) > 0 {
		return m.Payload
	}
	// 退而求其次：逐行取非注释、非 HEADER 行。
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "payload:") || strings.HasPrefix(line, "-") == false {
			continue
		}
		out = append(out, strings.TrimPrefix(line, "- "))
	}
	return out
}

// fetchPayload 从 HTTP 拉取规则集。
func fetchPayload(url string) []string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	data := make([]byte, 0, 1<<20)
	buf := make([]byte, 32*1024)
	for len(data) < 1<<20 {
		n, e := resp.Body.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if e != nil {
			break
		}
	}
	return extractPayload(data)
}
