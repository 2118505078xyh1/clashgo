package autogroup

import "testing"

func TestBuild(t *testing.T) {
	nodes := []string{
		"香港 01", "日本东京", "US Los Angeles", "新加坡节点",
		"美国 剩余流量 100G", // should be excluded by excludeRe
		"普通节点", "🇬🇧 London", "德国 Frankfurt",
	}
	groups := Build(nodes)
	if len(groups) == 0 {
		t.Fatal("no groups built")
	}
	byCode := map[string]Group{}
	for _, g := range groups {
		byCode[g.Code] = g
	}
	if g, ok := byCode["HK"]; !ok || len(g.Members) != 1 {
		t.Errorf("HK group: %v", g)
	}
	if g, ok := byCode["JP"]; !ok || len(g.Members) != 1 {
		t.Errorf("JP group: %v", g)
	}
	if g, ok := byCode["US"]; !ok || len(g.Members) != 1 {
		t.Errorf("US group: %v", g)
	}
	// "美国 剩余..." should be excluded.
	if g, ok := byCode["US"]; ok {
		for _, m := range g.Members {
			if m == "美国 剩余流量 100G" {
				t.Error("excluded node appeared in US group")
			}
		}
	}
	if _, ok := byCode["GB"]; !ok {
		t.Error("GB group missing")
	}
}
