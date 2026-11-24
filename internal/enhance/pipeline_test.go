package enhance

import (
	"strings"
	"testing"

	"clashgo/internal/config"
)

func TestPipelineEndToEnd(t *testing.T) {
	freshProfileDir(t)
	profile := []byte(`port: 7890
proxies:
  - name: old
    type: ss
proxy-groups:
  - name: SELECT
    type: select
    proxies: [old, DIRECT]
rules:
  - MATCH,DIRECT
`)
	db := &config.ProfilesDB{Items: []*config.PrfItem{
		{UID: "Merge", Type: config.ProfileMerge, File: "merge.yaml"},
		{UID: "r1", Type: config.ProfileRules, File: "r1.yaml"},
	}}
	// Write attachment files.
	writeTemp := func(name, content string) string {
		p := tempFile(t, name, content)
		return p
	}
	db.Items[0].File = writeTemp("merge.yaml", "port: 9999\ncustomkey: hello\n")
	db.Items[1].File = writeTemp("r1.yaml", "prepend: []\nappend:\n  - TEST,DIRECT\ndelete: []\n")

	item := &config.PrfItem{
		Name: "test",
		Option: &config.PrfOption{
			Merge: "Merge", Rules: "r1",
		},
	}
	s := config.DefaultSettings()
	result, err := Execute(profile, item, db, s)
	if err != nil {
		t.Fatal(err)
	}
	// Control-plane fields win: merge's port:9999 is discarded, and the
	// HTTP port is now owned by settings (default 7899).
	if result.Config["port"] != s.HTTPPort {
		t.Errorf("control plane port: got %v want %d", result.Config["port"], s.HTTPPort)
	}
	if result.Config["customkey"] != "hello" {
		t.Error("merge custom key missing")
	}
	rules := result.Config["rules"].([]any)
	if len(rules) < 2 || rules[len(rules)-1] != "TEST,DIRECT" {
		t.Errorf("seq rules append: %v", rules)
	}
	out, err := Marshal(result.Config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "customkey: hello") {
		t.Error("marshal lost keys")
	}
}
