// Package validate performs semantic validation of a generated 自研内核 config,
// beyond YAML syntax. It catches problems that yaml.Unmarshal cannot: port
// ranges, dangling proxy-group references, invalid DNS fields, duplicate names.
package validate

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"clashgo/internal/yaml"
)

// Issue is one validation problem.
type Issue struct {
	Level   string // "error" | "warning"
	Message string
}

// Result holds validation findings.
type Result struct {
	Valid  bool
	Issues []Issue
}

// Validate checks a raw 自研内核 YAML config for semantic problems.
func Validate(data []byte) Result {
	var root map[string]any
	r := Result{Valid: true}
	if err := yaml.Unmarshal(data, &root); err != nil {
		r.Valid = false
		r.Issues = append(r.Issues, Issue{"error", "YAML 解析失败: " + err.Error()})
		return r
	}
	addErr := func(f string, a ...any) {
		r.Valid = false
		r.Issues = append(r.Issues, Issue{"error", fmt.Sprintf(f, a...)})
	}
	addWarn := func(f string, a ...any) {
		r.Issues = append(r.Issues, Issue{"warning", fmt.Sprintf(f, a...)})
	}

	// Port validation.
	for _, key := range []string{"mixed-port", "port", "socks-port", "redir-port", "tproxy-port"} {
		if v, ok := root[key]; ok {
			p := toInt(v)
			if p < 0 || p > 65535 {
				addErr("%s 端口 %d 超出范围 (0-65535)", key, p)
			}
		}
	}

	// Collect proxies + providers names.
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "PASS-RULE": true}
	for _, item := range toSlice(root["proxies"]) {
		if name := fieldString(item, "name"); name != "" {
			if known[name] {
				addWarn("重复的节点名称: %s", name)
			}
			known[name] = true
		}
	}
	for _, item := range toSlice(root["proxy-providers"]) {
		if name := fieldString(item, "name"); name != "" {
			known[name] = true
		}
	}

	// Proxy-group member references (warning + degradation, not hard error).
	groupNames := map[string]bool{}
	for _, item := range toSlice(root["proxy-groups"]) {
		name := fieldString(item, "name")
		if name == "" {
			addErr("代理组缺少 name 字段")
			continue
		}
		groupNames[name] = true
	}
	for _, item := range toSlice(root["proxy-groups"]) {
		gname := fieldString(item, "name")
		for _, member := range toStringSlice(field(item, "proxies")) {
			if !known[member] && !groupNames[member] {
				addWarn("代理组 %s 引用了不存在的节点 %s（将回退到 DIRECT）", gname, member)
			}
		}
	}

	// DNS validation.
	if dns, ok := root["dns"].(map[string]any); ok {
		if mode, _ := dns["enhanced-mode"].(string); mode != "" && mode != "fake-ip" && mode != "redir-host" && mode != "normal" {
			addWarn("dns.enhanced-mode 取值异常: %s", mode)
		}
		if rangeStr, ok := dns["fake-ip-range"].(string); ok && rangeStr != "" {
			if _, _, err := net.ParseCIDR(rangeStr); err != nil {
				addErr("dns.fake-ip-range 不是合法 CIDR: %s", rangeStr)
			}
		}
		for _, key := range []string{"nameserver", "fallback"} {
			if arr := toStringSlice(dns[key]); len(arr) > 0 {
				for _, ns := range arr {
					if strings.HasPrefix(ns, "https://") || strings.HasPrefix(ns, "http://") {
						continue
					}
					if _, _, err := net.ParseCIDR(ns); err == nil {
						continue
					}
					if net.ParseIP(stripPort(ns)) == nil && !isDomain(ns) {
						addWarn("DNS 服务器地址可能无效: %s", ns)
					}
				}
			}
		}
	}

	// TUN validation.
	if tun, ok := root["tun"].(map[string]any); ok {
		if stack, _ := tun["stack"].(string); stack != "" {
			switch strings.ToLower(stack) {
			case "gvisor", "system", "mixed", "mips":
			default:
				addWarn("tun.stack 取值异常: %s", stack)
			}
		}
	}
	return r
}

func field(m any, key string) any {
	if mm, ok := m.(map[string]any); ok {
		return mm[key]
	}
	return nil
}
func fieldString(m any, key string) string {
	s, _ := field(m, key).(string)
	return s
}
func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
func toSlice(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}
func toStringSlice(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func stripPort(s string) string {
	if i := strings.LastIndex(s, ":"); i > 0 && strings.Count(s, ":") == 1 {
		return s[:i]
	}
	return s
}
func isDomain(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t") {
		return false
	}
	return true
}
