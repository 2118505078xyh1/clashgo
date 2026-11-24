package ruleindex

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestIPTreeLongestPrefix(t *testing.T) {
	trie := NewIPTree()
	trie.Insert(mustPrefix(t, "10.0.0.0/8"), 100, "a")
	trie.Insert(mustPrefix(t, "10.1.0.0/16"), 50, "b")
	trie.Insert(mustPrefix(t, "10.1.2.0/24"), 10, "c")

	cases := []struct {
		ip      string
		adapter string
		prio    int
		ok      bool
	}{
		{"10.1.2.3", "c", 10, true}, // /24 longest
		{"10.1.2.255", "c", 10, true},
		{"10.1.3.4", "b", 50, true},  // /16
		{"10.2.3.4", "a", 100, true}, // /8
		{"11.0.0.1", "", 0, false},
		{"192.168.1.1", "", 0, false},
	}
	for _, c := range cases {
		gotA, gotP, ok := trie.Match(mustAddr(t, c.ip))
		if ok != c.ok || gotA != c.adapter || gotP != c.prio {
			t.Errorf("Match(%s) = (%q, %d, %v), want (%q, %d, %v)",
				c.ip, gotA, gotP, ok, c.adapter, c.prio, c.ok)
		}
	}
}

func TestIPTreeTiePriority(t *testing.T) {
	trie := NewIPTree()
	trie.Insert(mustPrefix(t, "192.168.0.0/16"), 100, "low")
	trie.Insert(mustPrefix(t, "192.168.0.0/16"), 5, "high") // smaller priority wins

	if a, p, ok := trie.Match(mustAddr(t, "192.168.10.1")); !ok || a != "high" || p != 5 {
		t.Fatalf("tie: got (%q, %d, %v)", a, p, ok)
	}

	// A longer, lower-priority prefix must still beat a shorter one.
	trie.Insert(mustPrefix(t, "192.168.10.0/24"), 200, "longest")
	if a, p, ok := trie.Match(mustAddr(t, "192.168.10.1")); !ok || a != "longest" || p != 200 {
		t.Fatalf("longest prefix must win regardless of priority: got (%q, %d, %v)", a, p, ok)
	}
}

func TestIPTreeDefaultRoute(t *testing.T) {
	trie := NewIPTree()
	trie.Insert(mustPrefix(t, "0.0.0.0/0"), 9, "default")
	trie.Insert(mustPrefix(t, "172.16.0.0/12"), 1, "private")

	if a, p, ok := trie.Match(mustAddr(t, "8.8.8.8")); !ok || a != "default" || p != 9 {
		t.Fatalf("default route: got (%q, %d, %v)", a, p, ok)
	}
	if a, p, ok := trie.Match(mustAddr(t, "172.20.1.1")); !ok || a != "private" || p != 1 {
		t.Fatalf("specific over default: got (%q, %d, %v)", a, p, ok)
	}
}

func TestIPTreeIPv6(t *testing.T) {
	trie := NewIPTree()
	trie.Insert(mustPrefix(t, "2001:db8::/32"), 7, "v6")
	trie.Insert(mustPrefix(t, "2001:db8:1::/48"), 3, "v6-specific")
	trie.Insert(mustPrefix(t, "10.0.0.0/8"), 1, "v4")

	if a, p, ok := trie.Match(mustAddr(t, "2001:db8:1::1")); !ok || a != "v6-specific" || p != 3 {
		t.Fatalf("v6 specific: got (%q, %d, %v)", a, p, ok)
	}
	if a, p, ok := trie.Match(mustAddr(t, "2001:db8:ffff::1")); !ok || a != "v6" || p != 7 {
		t.Fatalf("v6 broad: got (%q, %d, %v)", a, p, ok)
	}
	if a, p, ok := trie.Match(mustAddr(t, "2001:dead::1")); ok {
		t.Fatalf("unexpected v6 match: (%q, %d)", a, p)
	}
	if a, p, ok := trie.Match(mustAddr(t, "10.9.9.9")); !ok || a != "v4" || p != 1 {
		t.Fatalf("v4 unaffected: got (%q, %d, %v)", a, p, ok)
	}
}

func TestIPTreeInvalidInput(t *testing.T) {
	trie := NewIPTree()
	trie.Insert(netip.Prefix{}, 1, "invalid")
	if _, _, ok := trie.Match(netip.Addr{}); ok {
		t.Fatal("invalid address must not match")
	}
}
