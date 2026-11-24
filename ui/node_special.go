package ui

import "strings"

// 代理模式里的特殊节点，不在节点组中重复展示。
func isSpecialNode(name string) bool {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "GLOBAL":
		return true
	}
	return false
}
