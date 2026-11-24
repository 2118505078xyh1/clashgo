package enhance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"clashgo/internal/yaml"

	"clashgo/internal/config"
	"clashgo/internal/paths"
	"clashgo/internal/safemode"
)

// ControlKeys are fields owned by the app; merge/script cannot override them.
var ControlKeys = []string{
	"external-controller", "external-controller-unix", "external-controller-pipe",
	"external-controller-cors", "secret", "mixed-port", "socks-port", "port",
	"redir-port", "tproxy-port", "mode", "allow-lan", "log-level", "ipv6",
	"unified-delay",
}

// Step is one pipeline stage's before/after snapshot. BeforeJSON/AfterJSON
// serialize only the top-level keys this stage changed, so the diff viewer can
// show a compact side-by-side view instead of the whole config. Values are
// truncated to keep the Step graph cheap to carry through runtime.Result.
type Step struct {
	Name        string
	ChangedKeys []string
	BeforeJSON  string
	AfterJSON   string
	Level       string // "info" (default) or "warn" when keys were removed
}

// Result holds the pipeline output, step diffs and any script logs.
type Result struct {
	Config Mapping
	Logs   map[string][]string
	Steps  []Step
}

// Execute runs the full enhance pipeline on a profile's raw YAML.
func Execute(profileBytes []byte, item *config.PrfItem, db *config.ProfilesDB, s *config.Settings) (*Result, error) {
	composeLogs := map[string][]string{}
	var root Mapping
	if item != nil && item.Type == config.ProfileComposition && db != nil {
		resolved, clogs, err := ResolveComposition(item, db)
		if err != nil {
			return nil, err
		}
		root = resolved
		for k, v := range clogs {
			composeLogs[k] = append(composeLogs[k], v...)
		}
	} else if err := yaml.Unmarshal(profileBytes, &root); err != nil {
		return nil, err
	}
	cfg := LowercaseTop(root)
	logs := composeLogs
	var steps []Step
	// snapshot records which top-level keys changed in a pipeline stage and
	// the before/after values of exactly those keys.
	snapshot := func(name string, before map[string]string) {
		after := topSnapshot(cfg)
		var changed, removed []string
		for k, v := range after {
			if before[k] != v {
				changed = append(changed, k)
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				changed = append(changed, k)
				removed = append(removed, k)
			}
		}
		sort.Strings(changed)
		level := "info"
		if len(removed) > 0 {
			level = "warn"
		}
		steps = append(steps, Step{
			Name:        name,
			ChangedKeys: changed,
			BeforeJSON:  diffJSON(changed, before),
			AfterJSON:   diffJSON(changed, after),
			Level:       level,
		})
	}
	before := topSnapshot(cfg)

	// 1. seq: rules → proxies → groups
	opt := &config.PrfOption{}
	if item != nil {
		if item.Option != nil {
			opt = item.Option
		}
	}
	applySeq := func(uid, field string) {
		if uid == "" {
			return
		}
		data := loadAttachment(db, uid)
		if len(data) == 0 {
			return
		}
		var seq SeqMap
		if yaml.Unmarshal(data, &seq) != nil {
			return
		}
		cfg = UseSeq(cfg, seq, field)
	}
	applySeq(opt.Rules, "rules")
	applySeq(opt.Proxies, "proxies")
	applySeq(opt.Groups, "proxy-groups")
	snapshot("seq 序列合并", before)

	// 2. app settings (merge_default_config) + control plane snapshot.
	before = topSnapshot(cfg)
	applySettings(cfg, s)
	snapshot("应用设置", before)
	controls := captureControls(cfg, s)

	// 3. global merge → global script, then profile merge → profile script.
	applyMerge := func(uid string) {
		if uid == "" {
			return
		}
		data := loadAttachment(db, uid)
		if len(data) == 0 {
			return
		}
		var m Mapping
		if yaml.Unmarshal(data, &m) != nil {
			return
		}
		cfg = UseMerge(cfg, m)
	}
	// 脚本附件（JS/Lua）不受支持：纯 Go 项目不需要脚本引擎。
	// 配置增强保留 merge / seq / 字段级 overlay 等纯数据操作。
	before = topSnapshot(cfg)
	applyMerge("Merge")
	applyMerge(opt.Merge)
	snapshot("Merge 扩展", before)

	// 4. enforce control-plane fields.
	before = topSnapshot(cfg)
	enforceControls(cfg, controls)
	snapshot("控制面保护", before)

	// 4.5 builtin transforms (a reference GUI's the builtin hysteria ALPN fix): normalize hysteria
	// alpn from a string to a single-element slice (自研内核 requires a slice).
	applyBuiltinTransforms(cfg)

	// 4.6 expand include-all directives into explicit proxies/use lists.
	// This runs before finalize's cleanupGroups so the injected references
	// are not mistaken for missing proxies.
	before = topSnapshot(cfg)
	ApplyIncludeAll(cfg, logs)
	snapshot("include-all 展开", before)

	// 5. finalize: TUN MTU, LAN bind, cleanup proxy groups, sort.
	finalize(cfg, s)

	// 5.5 safe mode: strip listeners/tunnels/controller when enabled.
	if s.SafeMode {
		before = topSnapshot(cfg)
		safemode.ApplySafe(cfg, safemode.SafeSettings{SafeMode: true})
		snapshot("安全模式加固", before)
	}

	return &Result{Config: cfg, Logs: logs, Steps: steps}, nil
}

// maxStepDiffValueBytes bounds each serialized value stored in a Step so a
// large subscription cannot blow up the in-memory step graph / UI list.
const maxStepDiffValueBytes = 2000

// topSnapshot serializes each top-level key's value. The string doubles as a
// cheap change detector and as the value shown in the pipeline diff viewer.
func topSnapshot(cfg Mapping) map[string]string {
	out := map[string]string{}
	for k, v := range cfg {
		out[k] = stepValue(v)
	}
	return out
}

func stepValue(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%q", fmt.Sprint(v))
	}
	s := string(b)
	if len(s) > maxStepDiffValueBytes {
		s = s[:maxStepDiffValueBytes] + "\n… (truncated)"
	}
	return s
}

// diffJSON assembles a JSON object of only the changed keys, using the already
// serialized per-key values from a snapshot.
func diffJSON(keys []string, snap map[string]string) string {
	if len(keys) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteString("{\n")
	written := 0
	for _, k := range keys {
		v, ok := snap[k]
		if !ok {
			continue
		}
		kb, _ := json.Marshal(k)
		if written > 0 {
			b.WriteString(",\n")
		}
		b.WriteString("  ")
		b.Write(kb)
		b.WriteString(": ")
		b.WriteString(v)
		written++
	}
	b.WriteString("\n}")
	return b.String()
}

// loadAttachment resolves an attachment UID to its file bytes.
func loadAttachment(db *config.ProfilesDB, uid string) []byte {
	item := attachment(db, uid)
	if item == nil || item.File == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(paths.Profiles, item.File))
	if err != nil {
		return nil
	}
	return data
}

func attachment(db *config.ProfilesDB, uid string) *config.PrfItem {
	if db == nil {
		return nil
	}
	return db.Find(uid)
}

func attachmentFile(db *config.ProfilesDB, uid string) string {
	item := attachment(db, uid)
	if item == nil {
		return ""
	}
	return item.File
}

func applySettings(cfg Mapping, s *config.Settings) {
	controls := map[string]any{
		"mixed-port": s.MixedPort, "external-controller": s.ExternalController,
		"secret": s.Secret, "mode": s.Mode, "log-level": s.LogLevel,
		"ipv6": true, "unified-delay": true,
	}
	for k, v := range controls {
		cfg[k] = v
	}
	// Disable unused port listeners by removing their config keys.
	if s.SocksEnabled {
		cfg["socks-port"] = s.SocksPort
	} else {
		delete(cfg, "socks-port")
	}
	if s.HTTPEnabled {
		cfg["port"] = s.HTTPPort
	} else {
		delete(cfg, "port")
	}
	if s.ExternalController != "" {
		cfg["external-controller-cors"] = map[string]any{
			"allow-private-network": true, "allow-origins": []string{"*"},
		}
	}
	// DNS override: apply the user's nameservers while preserving the rest of
	// the subscription's DNS config (hosts, fake-ip-filter, policies...).
	if s.EnableDNSOverride && strings.TrimSpace(s.Nameserver) != "" {
		dns, _ := cfg["dns"].(Mapping)
		if dns == nil {
			dns = Mapping{}
		}
		var servers []any
		for _, ns := range strings.Split(s.Nameserver, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				servers = append(servers, ns)
			}
		}
		if len(servers) > 0 {
			dns["enable"] = true
			dns["nameserver"] = servers
			cfg["dns"] = dns
		}
	}
	tun := map[string]any{"enable": s.EnableTUN, "stack": s.TUNStack, "auto-route": s.TUNAutoRoute}
	if existing, ok := cfg["tun"].(Mapping); ok {
		for k, v := range existing {
			tun[k] = v
		}
		tun["enable"], tun["stack"], tun["auto-route"] = s.EnableTUN, s.TUNStack, s.TUNAutoRoute
	}
	if s.EnableTUN {
		tun["auto-detect-interface"] = true
		tun["dns-hijack"] = []string{"any:53"}
		if tun["mtu"] == nil {
			tun["mtu"] = 1500
		}
		// Exclude private networks from TUN routing so LAN devices and local
		// services stay reachable (idea from common practice).
		privateRoutes := []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10"}
		existingRoutes := toStringSlice(tun["route-exclude-address"])
		merged := append([]any{}, privateRoutes...)
		for _, r := range existingRoutes {
			merged = append(merged, r)
		}
		tun["route-exclude-address"] = merged
		dns, _ := cfg["dns"].(Mapping)
		if dns == nil {
			dns = Mapping{}
		}
		dns["enable"] = true
		dns["enhanced-mode"] = "fake-ip"
		if dns["fake-ip-range"] == nil {
			dns["fake-ip-range"] = "198.18.0.1/16"
		}
		// IPv6 fake-ip range is required for AAAA resolution when TUN is on.
		if dns["fake-ip-range6"] == nil {
			dns["fake-ip-range6"] = "2001:2::0/64"
		}
		cfg["dns"] = dns
	}
	cfg["tun"] = tun
}

func captureControls(cfg Mapping, s *config.Settings) map[string]any {
	out := map[string]any{}
	for _, k := range ControlKeys {
		v, ok := cfg[k]
		if !ok {
			continue
		}
		// Ports disabled in settings are not authoritative — let them stay removed.
		if k == "socks-port" && !s.SocksEnabled {
			continue
		}
		if k == "port" && !s.HTTPEnabled {
			continue
		}
		out[k] = v
	}
	return out
}

func enforceControls(cfg Mapping, controls map[string]any) {
	for _, k := range ControlKeys {
		if v, ok := controls[k]; ok {
			cfg[k] = v
		} else {
			delete(cfg, k)
		}
	}
}

func finalize(cfg Mapping, s *config.Settings) {
	// Ensure TUN MTU.
	if tun, ok := cfg["tun"].(Mapping); ok {
		if tun["mtu"] == nil {
			tun["mtu"] = 1500
		}
	}
	// LAN bind address.
	if allow, _ := cfg["allow-lan"].(bool); allow {
		if bind, ok := cfg["bind-address"].(string); ok && (bind == "127.0.0.1" || bind == "::1") {
			cfg["bind-address"] = "*"
		}
	}
	// Cleanup proxy groups referencing missing proxies.
	cleanupGroups(cfg)
}

func cleanupGroups(cfg Mapping) {
	known := map[string]bool{}
	for _, p := range toSlice(cfg["proxies"]) {
		if n := itemName(p); n != "" {
			known[n] = true
		}
	}
	for _, p := range toSlice(cfg["proxy-providers"]) {
		if m, ok := p.(Mapping); ok {
			if n, _ := m["name"].(string); n != "" {
				known[n] = true
			}
		}
	}
	whitelist := map[string]bool{
		"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "PASS-RULE": true,
	}
	groups := toSlice(cfg["proxy-groups"])
	for _, g := range groups {
		gm, ok := g.(Mapping)
		if !ok {
			continue
		}
		pl := toSlice(gm["proxies"])
		var cleaned []any
		for _, p := range pl {
			if n, ok := p.(string); ok {
				if known[n] || whitelist[n] {
					cleaned = append(cleaned, p)
				}
				continue
			}
			cleaned = append(cleaned, p) // non-string entries (dialer-proxy etc.) keep
		}
		gm["proxies"] = cleaned
	}
}

// Marshal renders the config with deterministic key order.
func Marshal(cfg Mapping) ([]byte, error) {
	priority := []string{
		"mixed-port", "port", "socks-port", "redir-port", "tproxy-port",
		"allow-lan", "bind-address", "mode", "log-level", "ipv6", "unified-delay",
		"external-controller", "external-controller-cors", "secret", "dns", "tun",
	}
	last := []string{"proxies", "proxy-providers", "proxy-groups", "rule-providers", "rules"}
	node := SortKeys(cfg, priority, last)
	return yaml.Marshal(node)
}

var _ = strconv.Itoa
var _ = strings.ToLower
