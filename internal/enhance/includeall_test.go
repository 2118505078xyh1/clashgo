package enhance

import (
	"reflect"
	"strings"
	"testing"

	"clashgo/internal/config"
)

func namesOf(v any) []string {
	var out []string
	for _, item := range toSlice(v) {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestApplyIncludeAllExpandAndSort(t *testing.T) {
	cfg := Mapping{
		"proxies": []any{
			Mapping{"name": "zeta", "type": "ss"},
			Mapping{"name": "Alpha", "type": "ss"},
			Mapping{"name": "beta", "type": "ss"},
		},
		"proxy-providers": Mapping{
			"provider-z": Mapping{"type": "http"},
			"provider-a": Mapping{"type": "http"},
		},
		"proxy-groups": []any{
			Mapping{
				"name": "AUTO", "type": "select",
				"proxies":             []any{"DIRECT"},
				"include-all":         true,
				"include-all-proxies": false,
			},
		},
	}
	logs := map[string][]string{}
	ApplyIncludeAll(cfg, logs)

	g := cfg["proxy-groups"].([]any)[0].(Mapping)
	want := []string{"DIRECT", "Alpha", "beta", "zeta"}
	if got := namesOf(g["proxies"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("proxies = %v, want %v", got, want)
	}
	if got := namesOf(g["use"]); !reflect.DeepEqual(got, []string{"provider-a", "provider-z"}) {
		t.Fatalf("use = %v, want sorted provider names", got)
	}
	for _, k := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
		if _, ok := g[k]; ok {
			t.Errorf("directive %q not removed", k)
		}
	}
	if len(logs[includeAllLogKey]) == 0 {
		t.Error("expected an include-all log entry")
	}
}

func TestApplyIncludeAllProxiesOnly(t *testing.T) {
	cfg := Mapping{
		"proxies": []any{
			Mapping{"name": "b"}, Mapping{"name": "a"},
		},
		"proxy-providers": []any{Mapping{"name": "p1"}},
		"proxy-groups": []any{Mapping{
			"name": "P", "type": "select", "include-all-proxies": true,
		}},
	}
	ApplyIncludeAll(cfg, map[string][]string{})
	g := cfg["proxy-groups"].([]any)[0].(Mapping)
	if got := namesOf(g["proxies"]); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("proxies = %v, want [a b]", got)
	}
	if _, ok := g["use"]; ok {
		t.Error("include-all-proxies must not touch `use`")
	}
}

func TestApplyIncludeAllProvidersOnly(t *testing.T) {
	cfg := Mapping{
		"proxies":         []any{Mapping{"name": "a"}},
		"proxy-providers": Mapping{"p2": Mapping{}, "p1": Mapping{}},
		"proxy-groups": []any{Mapping{
			"name": "PR", "type": "select",
			"proxies": []any{"DIRECT"}, "include-all-providers": true,
		}},
	}
	ApplyIncludeAll(cfg, map[string][]string{})
	g := cfg["proxy-groups"].([]any)[0].(Mapping)
	if got := namesOf(g["proxies"]); !reflect.DeepEqual(got, []string{"DIRECT"}) {
		t.Fatalf("proxies changed: %v", got)
	}
	if got := namesOf(g["use"]); !reflect.DeepEqual(got, []string{"p1", "p2"}) {
		t.Fatalf("use = %v, want [p1 p2]", got)
	}
}

func TestApplyIncludeAllDedup(t *testing.T) {
	cfg := Mapping{
		"proxies": []any{
			Mapping{"name": "b"}, Mapping{"name": "a"}, Mapping{"name": "b"},
		},
		"proxy-groups": []any{Mapping{
			"name": "D", "type": "select",
			"proxies":     []any{"a", "a", "DIRECT"},
			"include-all": true,
		}},
	}
	ApplyIncludeAll(cfg, map[string][]string{})
	g := cfg["proxy-groups"].([]any)[0].(Mapping)
	if got := namesOf(g["proxies"]); !reflect.DeepEqual(got, []string{"a", "DIRECT", "b"}) {
		t.Fatalf("proxies = %v, want deduped [a DIRECT b]", got)
	}
}

func TestApplyIncludeAllFilterAndFallback(t *testing.T) {
	cfg := Mapping{
		"proxies": []any{
			Mapping{"name": "HK-01", "type": "ss"},
			Mapping{"name": "US-01", "type": "ss"},
			Mapping{"name": "HK-02", "type": "ss"},
		},
		"proxy-groups": []any{Mapping{
			"name": "FILTER", "type": "select",
			"filter":              "^HK-`02$",
			"include-all-proxies": true,
		}},
	}
	ApplyIncludeAll(cfg, map[string][]string{})
	filtered := namesOf(cfg["proxy-groups"].([]any)[0].(Mapping)["proxies"])
	// HK-01 matches the first pattern, HK-02 matches both; dedup keeps one.
	if !reflect.DeepEqual(filtered, []string{"HK-01", "HK-02"}) {
		t.Fatalf("filtered = %v, want [HK-01 HK-02]", filtered)
	}

	// With no proxies and no providers, 自研内核 falls back to empty-fallback.
	emptyCfg := Mapping{
		"proxy-groups": []any{Mapping{
			"name": "EMPTY", "type": "select",
			"empty-fallback":      "DIRECT",
			"include-all-proxies": true,
		}},
	}
	ApplyIncludeAll(emptyCfg, map[string][]string{})
	empty := emptyCfg["proxy-groups"].([]any)[0].(Mapping)
	if got := namesOf(empty["proxies"]); !reflect.DeepEqual(got, []string{"DIRECT"}) {
		t.Fatalf("fallback = %v, want [DIRECT]", got)
	}
}

func TestApplyIncludeAllNoopAndWeakBool(t *testing.T) {
	cfg := Mapping{
		"proxies": []any{Mapping{"name": "a"}},
		"proxy-groups": []any{
			Mapping{"name": "NORMAL", "type": "select", "proxies": []any{"a"}},
			Mapping{"name": "WEAK", "type": "select", "include-all": "false"},
			Mapping{"name": "ON", "type": "select", "include-all-proxies": 1},
		},
	}
	ApplyIncludeAll(cfg, map[string][]string{})
	groups := cfg["proxy-groups"].([]any)
	if _, ok := groups[0].(Mapping)["proxies"]; !ok {
		t.Fatal("normal group lost its proxies")
	}
	if _, ok := groups[1].(Mapping)[keyIncludeAll]; !ok {
		t.Fatal("include-all: false should be removed as a directive")
	}
	if got := namesOf(groups[1].(Mapping)["proxies"]); len(got) != 0 {
		t.Fatalf("include-all: false should not expand, got %v", got)
	}
	if got := namesOf(groups[2].(Mapping)["proxies"]); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("weak bool 1 = %v, want [a]", got)
	}
}

func TestApplyIncludeAllIntegrationWithCleanup(t *testing.T) {
	// Finalize's cleanupGroups must keep the freshly injected references.
	cfg := Mapping{
		"proxies": []any{Mapping{"name": "x", "type": "ss"}},
		"proxy-groups": []any{Mapping{
			"name": "ALL", "type": "select", "include-all-proxies": true,
		}},
	}
	logs := map[string][]string{}
	ApplyIncludeAll(cfg, logs)
	finalize(cfg, config.DefaultSettings())
	g := cfg["proxy-groups"].([]any)[0].(Mapping)
	if got := namesOf(g["proxies"]); !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatalf("cleanup dropped expanded proxy: %v", got)
	}
	if !strings.Contains(logs[includeAllLogKey][0], "ALL") {
		t.Fatalf("log does not mention group name: %v", logs)
	}
}
