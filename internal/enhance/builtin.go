package enhance

import "strings"

// applyBuiltinTransforms applies 自研内核 compatibility fixes that a reference GUI
// Rev ships as builtin scripts (e.g. the builtin hysteria ALPN fix.js).
func applyBuiltinTransforms(cfg Mapping) {
	// hysteria / hysteria2 alpn must be a list, not a bare string.
	for _, item := range toSlice(cfg["proxies"]) {
		pm, ok := item.(Mapping)
		if !ok {
			continue
		}
		ptype, _ := pm["type"].(string)
		if !strings.HasPrefix(strings.ToLower(ptype), "hysteria") {
			continue
		}
		if alpn, ok := pm["alpn"].(string); ok && alpn != "" {
			pm["alpn"] = []any{alpn}
		}
	}
}
