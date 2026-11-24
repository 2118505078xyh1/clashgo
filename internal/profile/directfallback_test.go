package profile

import "testing"

func TestEnsureDirectFallbackAddsRulesWhenNoDirect(t *testing.T) {
	src := "proxies:\n  - name: a\nrules:\n  - MATCH,PROXY\n"
	got := EnsureDirectFallback(src)
	want := "proxies:\n  - name: a\nrules:\n  - GEOSITE,geolocation-cn,DIRECT\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n"
	if got != want {
		t.Fatalf("unexpected result:\n got: %q\nwant: %q", got, want)
	}
}

func TestEnsureDirectFallbackKeepsExistingDirect(t *testing.T) {
	src := "rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY\n"
	if got := EnsureDirectFallback(src); got != src {
		t.Fatalf("existing DIRECT rule should be untouched, got %q", got)
	}
}

func TestEnsureDirectFallbackSkipsInlineArray(t *testing.T) {
	src := "rules: [MATCH,PROXY]\n"
	if got := EnsureDirectFallback(src); got != src {
		t.Fatalf("inline array should stay unchanged, got %q", got)
	}
}

func TestEnsureDirectFallbackWithoutRulesSection(t *testing.T) {
	src := "proxies: []\n"
	if got := EnsureDirectFallback(src); got != src {
		t.Fatalf("config without rules should stay unchanged, got %q", got)
	}
}
