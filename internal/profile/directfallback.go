package profile

import "strings"

// 直连兜底规则。导入真实 Clash YAML 时，如果订阅只带 MATCH,PROXY，
// 节点一旦失效整机会断网。这里在没有 DIRECT 规则时补两条国内直连。
const (
	directFallbackRule1 = "GEOSITE,geolocation-cn,DIRECT"
	directFallbackRule2 = "GEOIP,CN,DIRECT"
)

// EnsureDirectFallback 在订阅配置完全没有 DIRECT 规则时，于 rules 列表
// 最前面插入两条国内直连规则，保证节点失效时国内流量仍可直连。
//
// 已有 DIRECT 规则时原样返回，不改动用户自己的分流逻辑。
// rules 为内联数组（rules: [A,B]）时无法安全插入，同样原样返回。
func EnsureDirectFallback(yamlText string) string {
	if hasDirectRule(yamlText) {
		return yamlText
	}

	lines := strings.Split(yamlText, "\n")
	// 末尾换行不参与逐行处理，最后统一补回，避免多出一个空行。
	trailingNewline := false
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
		trailingNewline = true
	}

	var out strings.Builder
	inserted := false
	inRules := false
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if !inserted && strings.TrimSpace(trimmed) != "" &&
			strings.HasPrefix(strings.TrimSpace(trimmed), "rules:") {
			inRules = true
			out.WriteString(trimmed)
			out.WriteString("\n")
			// 内联数组写法无法安全插入，放弃修改。
			if strings.Contains(trimmed, "[") {
				return yamlText
			}
			// 沿用原文件 rules 列表的实际缩进：YAML 里同一列表的子项缩进
			// 不一致会被解析成两个不同的块，后面的规则会整体丢失。
			indent := detectListIndent(lines, i)
			out.WriteString(indent + "- " + directFallbackRule1 + "\n")
			out.WriteString(indent + "- " + directFallbackRule2 + "\n")
			inserted = true
			continue
		}
		if inRules {
			// rules 段结束：遇到非列表项且缩进更小的键。
			t := strings.TrimSpace(trimmed)
			if t != "" && !strings.HasPrefix(t, "-") {
				inRules = false
			}
		}
		out.WriteString(trimmed)
		out.WriteString("\n")
	}
	if !inserted {
		return yamlText
	}
	result := out.String()
	if !trailingNewline {
		result = strings.TrimSuffix(result, "\n")
	}
	return result
}

// detectListIndent 找出 rules 列表第一项使用的缩进。
// 找不到列表项时返回空串（rules 是空列表）。
func detectListIndent(lines []string, rulesIdx int) string {
	for i := rulesIdx + 1; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(l), "-") {
			return "" // 下一行不是列表项：rules 是空列表
		}
		// 取 "- " 之前的空白作为缩进。
		return l[:len(l)-len(strings.TrimLeft(l, " \t"))]
	}
	return "  "
}

// hasDirectRule 判断配置里是否已经存在指向 DIRECT 的规则。
func hasDirectRule(yamlText string) bool {
	for _, line := range strings.Split(yamlText, "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "-") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(l, "-"))
		parts := strings.Split(body, ",")
		if len(parts) < 2 {
			continue
		}
		policy := strings.TrimSpace(parts[len(parts)-1])
		if strings.EqualFold(policy, "DIRECT") {
			return true
		}
	}
	return false
}
