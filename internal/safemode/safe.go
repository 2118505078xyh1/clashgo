package safemode

// SafeSettings is the subset of config.Settings that controls safe mode.
// Keeping it as a plain struct avoids a dependency from this package back to
// the config package.
type SafeSettings struct {
	SafeMode bool
}

// ApplySafe hardens a runtime Clash configuration in place:
//   - "listeners" and "tunnels" are removed (they would expose inbound ports),
//   - "external-controller" is emptied (no remote control endpoint),
//   - "allow-lan" is disabled (never listen on all interfaces).
//
// It is a no-op when SafeMode is false or cfg is nil. The returned slice
// lists, in a stable order, the keys that were actually changed.
func ApplySafe(cfg map[string]any, settings SafeSettings) []string {
	if !settings.SafeMode || cfg == nil {
		return nil
	}
	var changed []string

	// Drop inbound listener definitions entirely.
	for _, key := range []string{"listeners", "tunnels"} {
		if _, ok := cfg[key]; ok {
			delete(cfg, key)
			changed = append(changed, key)
		}
	}

	// An external controller allows third parties to drive the core.
	if v, ok := cfg["external-controller"]; !ok || !isEmptyString(v) {
		cfg["external-controller"] = ""
		changed = append(changed, "external-controller")
	}

	// Binding to 0.0.0.0 would make the proxy reachable from the LAN.
	if v, ok := cfg["allow-lan"]; !ok || !isFalse(v) {
		cfg["allow-lan"] = false
		changed = append(changed, "allow-lan")
	}

	return changed
}

func isEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s == ""
}

func isFalse(v any) bool {
	b, ok := v.(bool)
	return ok && !b
}
