package ruleindex

import "testing"

func TestDomainTrieSuffixMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Insert("google.com", 10, "proxy")
	trie.Insert("baidu.com", 5, "direct")

	cases := []struct {
		host     string
		adapter  string
		priority int
		ok       bool
	}{
		{"google.com", "proxy", 10, true},
		{"www.google.com", "proxy", 10, true},
		{"a.b.google.com", "proxy", 10, true},
		{"sub.baidu.com", "direct", 5, true},
		{"GOOGLE.COM", "proxy", 10, true}, // case insensitive
		{"www.google.com.", "proxy", 10, true},
		{"notgoogle.com", "", 0, false}, // label boundary matters
		{"unknown.com", "", 0, false},
	}
	for _, c := range cases {
		gotAdapter, gotPrio, ok := trie.Match(c.host)
		if ok != c.ok || gotAdapter != c.adapter || gotPrio != c.priority {
			t.Errorf("Match(%q) = (%q, %d, %v), want (%q, %d, %v)",
				c.host, gotAdapter, gotPrio, ok, c.adapter, c.priority, c.ok)
		}
	}
}

func TestDomainTrieExactMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Insert("google.com", 10, "suffix-proxy")
	trie.InsertExact("www.google.com", 1, "exact-block")

	// Exact rule has smaller priority and must win on the exact host.
	if a, p, ok := trie.Match("www.google.com"); !ok || a != "exact-block" || p != 1 {
		t.Fatalf("exact host: got (%q, %d, %v)", a, p, ok)
	}
	// For the bare domain only the suffix rule applies; the exact rule for
	// www.google.com must NOT match google.com.
	if a, p, ok := trie.Match("google.com"); !ok || a != "suffix-proxy" || p != 10 {
		t.Fatalf("bare domain: got (%q, %d, %v)", a, p, ok)
	}
	// A deeper host must not match the exact rule either.
	if a, p, ok := trie.Match("mail.www.google.com"); !ok || a != "suffix-proxy" || p != 10 {
		t.Fatalf("deeper host: got (%q, %d, %v)", a, p, ok)
	}
}

func TestDomainTriePriorityOrder(t *testing.T) {
	trie := NewDomainTrie()
	// Broad rule inserted first (higher priority number = earlier in config
	// order is NOT the case here; smaller number wins).
	trie.Insert("com", 100, "broad")
	trie.Insert("google.com", 10, "specific")
	trie.Insert("example.com", 10, "other")
	trie.Insert("google.com", 50, "later-same-suffix") // should be ignored

	if a, p, ok := trie.Match("a.google.com"); !ok || a != "specific" || p != 10 {
		t.Fatalf("overlapping suffixes: got (%q, %d, %v)", a, p, ok)
	}
	if a, p, ok := trie.Match("x.example.com"); !ok || a != "other" || p != 10 {
		t.Fatalf("equal priority: got (%q, %d, %v)", a, p, ok)
	}
	if a, p, ok := trie.Match("x.unknown.com"); !ok || a != "broad" || p != 100 {
		t.Fatalf("broad fallback: got (%q, %d, %v)", a, p, ok)
	}
}

func TestDomainTrieKeyword(t *testing.T) {
	trie := NewDomainTrie()
	trie.InsertKeyword("ads", 20, "reject")
	trie.Insert("example.com", 5, "allow")

	// Keyword wins because no suffix rule matches this host.
	if a, p, ok := trie.Match("ads.tracker.net"); !ok || a != "reject" || p != 20 {
		t.Fatalf("keyword match: got (%q, %d, %v)", a, p, ok)
	}
	// Suffix rule wins on priority when both match.
	if a, p, ok := trie.Match("ads.example.com"); !ok || a != "allow" || p != 5 {
		t.Fatalf("priority between keyword and suffix: got (%q, %d, %v)", a, p, ok)
	}
	if _, _, ok := trie.Match("clean.net"); ok {
		t.Fatal("unexpected match for clean.net")
	}
}

func TestDomainTrieEmpty(t *testing.T) {
	trie := NewDomainTrie()
	if _, _, ok := trie.Match("example.com"); ok {
		t.Fatal("empty trie should not match")
	}
}
