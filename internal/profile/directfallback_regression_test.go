package profile

import (
	"strings"
	"testing"

	"clashgo/internal/yaml"
)

// TestEnsureDirectFallbackKeepsExistingRules 验证插入兜底规则后，
// 原有的全部规则都还在。
//
// 这是一个真实踩过的坑：兜底规则用两空格缩进插入，而订阅文件用四空格
// 缩进，YAML 解析时把两种缩进当成两个不同的块，导致后面的规则全部丢失。
func TestEnsureDirectFallbackKeepsExistingRules(t *testing.T) {
	src := "rules:\n    - DOMAIN,a.com,PROXY\n    - DOMAIN,b.com,PROXY\n    - MATCH,PROXY\n"
	out := EnsureDirectFallback(src)

	var m map[string]any
	if err := yaml.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("解析失败: %v\n%s", err, out)
	}
	rules, _ := m["rules"].([]any)
	if len(rules) != 5 {
		t.Fatalf("规则数不对: got %d, want 5\n%s", len(rules), out)
	}
	if !strings.Contains(out, "DOMAIN,a.com,PROXY") {
		t.Fatalf("原有规则丢失:\n%s", out)
	}
	if rules[2] != "DOMAIN,a.com,PROXY" {
		t.Fatalf("兜底规则位置不对: %v", rules[2])
	}
}

// TestEnsureDirectFallbackMatchesListIndent 验证插入的规则沿用原缩进。
func TestEnsureDirectFallbackMatchesListIndent(t *testing.T) {
	for _, indent := range []string{"  ", "    ", "\t"} {
		src := "rules:\n" + indent + "- MATCH,PROXY\n"
		out := EnsureDirectFallback(src)
		if !strings.Contains(out, "\n"+indent+"- GEOSITE,geolocation-cn,DIRECT") {
			t.Fatalf("缩进不匹配 %q:\n%s", indent, out)
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("缩进 %q 解析失败: %v", indent, err)
		}
		rules, _ := m["rules"].([]any)
		if len(rules) != 3 {
			t.Fatalf("缩进 %q 规则数不对: %d", indent, len(rules))
		}
	}
}
