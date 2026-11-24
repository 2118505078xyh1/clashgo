package ruleindex

import (
	"net/netip"
	"testing"
)

// TestGeoIPRawDataValid parses every embedded CIDR string directly from the
// source map, ensuring the built-in data itself is well formed.
func TestGeoIPRawDataValid(t *testing.T) {
	for country, raw := range geoCIDRs {
		for _, s := range raw {
			if _, err := netip.ParsePrefix(s); err != nil {
				t.Errorf("[%s] invalid CIDR %q: %v", country, s, err)
			}
		}
	}
}

func TestGeoIPCidrsCN(t *testing.T) {
	got := GeoIPCidrs("cn")
	if len(got) < 100 {
		t.Fatalf("cn has only %d CIDRs, want >= 100", len(got))
	}
	for _, p := range got {
		if !p.IsValid() {
			t.Fatal("cn returned an invalid prefix")
		}
	}
	// Well-known Chinese addresses must be covered.
	checks := []struct {
		ip   string
		want bool
	}{
		{"114.114.114.114", true}, // China Telecom DNS
		{"1.0.1.1", true},
		{"8.8.8.8", false},
	}
	for _, c := range checks {
		a := netip.MustParseAddr(c.ip)
		found := false
		for _, p := range got {
			if p.Contains(a) {
				found = true
				break
			}
		}
		if found != c.want {
			t.Errorf("cn coverage for %s = %v, want %v", c.ip, found, c.want)
		}
	}
}

func TestGeoIPCidrsOtherCountries(t *testing.T) {
	for _, cc := range []string{"hk", "tw", "jp", "us", "sg"} {
		got := GeoIPCidrs(cc)
		if len(got) == 0 {
			t.Fatalf("%s returned no CIDRs", cc)
		}
		for _, p := range got {
			if !p.IsValid() {
				t.Fatalf("%s returned an invalid prefix", cc)
			}
		}
	}
}

func TestGeoIPCidrsCaseInsensitiveAndUnknown(t *testing.T) {
	lower := GeoIPCidrs("cn")
	upper := GeoIPCidrs(" CN ")
	if len(lower) != len(upper) {
		t.Fatal("country code lookup should be case/space insensitive")
	}
	if got := GeoIPCidrs("zz"); got != nil {
		t.Fatalf("unknown country should return nil, got %v", got)
	}
}

func TestGeoIPCidrsReturnsCopy(t *testing.T) {
	a := GeoIPCidrs("cn")
	b := GeoIPCidrs("cn")
	if len(a) == 0 {
		t.Fatal("no data")
	}
	a[0] = netip.Prefix{}
	if b[0] == (netip.Prefix{}) {
		t.Fatal("mutating returned slice corrupted the cached data")
	}
}
