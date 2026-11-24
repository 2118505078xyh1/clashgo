package enhance

import (
	"os"
	"path/filepath"
	"testing"

	"clashgo/internal/config"
	"clashgo/internal/paths"
)

func TestResolveComposition(t *testing.T) {
	freshProfileDir(t)
	write := func(name, content string) string {
		p := filepath.Join(paths.Profiles, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return name
	}
	baseFile := write("base.yaml", "port: 7890\nproxies:\n  - name: A\n    type: ss\nproxy-groups:\n  - name: SELECT\n    type: select\n    proxies: [A]\nrules:\n  - MATCH,DIRECT\n")
	c1File := write("c1.yaml", "proxies:\n  - name: B\n    type: ss\n  - name: C\n    type: vmess\n")
	c2File := write("c2.yaml", "proxies:\n  - name: D\n    type: trojan\n")

	db := &config.ProfilesDB{Items: []*config.PrfItem{
		{UID: "comp", Type: config.ProfileComposition, Name: "pool", Composition: &config.CompositionSpec{
			Base: "base", Contributors: []string{"c1", "c2"},
		}},
		{UID: "base", Type: config.ProfileLocal, File: baseFile},
		{UID: "c1", Type: config.ProfileRemote, File: c1File},
		{UID: "c2", Type: config.ProfileLocal, File: c2File},
	}}
	item := db.Find("comp")
	cfg, logs, err := ResolveComposition(item, db)
	if err != nil {
		t.Fatal(err)
	}
	proxies := toSlice(cfg["proxies"])
	if len(proxies) != 4 { // A + B + C + D
		t.Fatalf("expected 4 proxies, got %d: %v", len(proxies), proxies)
	}
	// Base fields inherited.
	if cfg["port"] != 7890 || cfg["rules"] == nil {
		t.Error("base fields not inherited")
	}
	// First selector group should include new names.
	groups := toSlice(cfg["proxy-groups"])
	if len(groups) == 0 {
		t.Fatal("no proxy-groups")
	}
	pg := groups[0].(Mapping)["proxies"].([]any)
	joined := ""
	for _, p := range pg {
		joined += p.(string) + ","
	}
	for _, n := range []string{"B", "C", "D"} {
		if !containsString(joined, n) {
			t.Errorf("selector missing injected node %s: %s", n, joined)
		}
	}
	_ = logs
}

func containsString(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}

func TestCompositionValidation(t *testing.T) {
	freshProfileDir(t)
	db := &config.ProfilesDB{Items: []*config.PrfItem{
		{UID: "comp", Type: config.ProfileComposition, Composition: &config.CompositionSpec{Contributors: []string{"comp"}}},
		{UID: "a", Type: config.ProfileLocal, File: "a.yaml"},
	}}
	_, _, err := ResolveComposition(db.Find("comp"), db)
	if err == nil {
		t.Error("self-reference should fail")
	}
}
