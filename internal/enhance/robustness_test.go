package enhance

import (
	"testing"

	"clashgo/internal/config"
)

func TestControlPlaneEnforcement(t *testing.T) {
	freshProfileDir(t)
	// A merge script tries to override app-owned fields; enforcement must win.
	profile := []byte("mixed-port: 1111\nmode: rule\nsecret: abc\n")
	db := &config.ProfilesDB{Items: []*config.PrfItem{
		{UID: "Merge", Type: config.ProfileMerge, File: "m2.yaml"},
	}}
	db.Items[0].File = tempFile(t, "m2.yaml", "mixed-port: 9999\nmode: global\nsecret: hacked\ncustom: ok\n")

	s := config.DefaultSettings()
	s.MixedPort = 2222
	s.Mode = "direct"
	item := &config.PrfItem{Name: "x", Option: &config.PrfOption{Merge: "Merge"}}
	res, err := Execute(profile, item, db, s)
	if err != nil {
		t.Fatal(err)
	}
	if res.Config["mixed-port"] != s.MixedPort {
		t.Errorf("mixed-port override leaked: %v", res.Config["mixed-port"])
	}
	if res.Config["mode"] != s.Mode {
		t.Errorf("mode override leaked: %v", res.Config["mode"])
	}
	if res.Config["secret"] != s.Secret {
		t.Errorf("secret override leaked: %v", res.Config["secret"])
	}
	if res.Config["custom"] != "ok" {
		t.Error("legit merge key discarded")
	}
}

func TestSeqDeleteByName(t *testing.T) {
	cfg := Mapping{
		"proxies": []any{
			Mapping{"name": "A"}, Mapping{"name": "B"}, Mapping{"name": "C"},
		},
	}
	out := UseSeq(cfg, SeqMap{Delete: []string{"B"}}, "proxies")
	proxies := out["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(proxies))
	}
	if proxies[0].(Mapping)["name"] != "A" || proxies[1].(Mapping)["name"] != "C" {
		t.Errorf("delete by name failed: %v", proxies)
	}
}
