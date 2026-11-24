// Package ruleindex provides dependency-free, high-performance data structures
// for indexing proxy rules: a reverse-label domain trie, a binary IP prefix
// trie, and a small built-in GeoIP CIDR database.
//
// The index structures are intended to be built once (at configuration load)
// and then queried concurrently. They use an RWMutex so that insertion and
// matching are safe to mix, although the intended fast path is a read-only
// population followed by concurrent Match calls.
package ruleindex

import (
	"strings"
	"sync"
)

// ruleEntry is the best rule recorded at a node. A smaller priority means
// the rule appeared earlier in the configuration and therefore wins.
type ruleEntry struct {
	adapter  string
	priority int
	set      bool
}

// better reports whether a candidate priority beats the currently held entry.
func betterPriority(p int, cur ruleEntry) bool {
	return !cur.set || p < cur.priority
}

// domainNode is a single node of the reverse-label domain trie.
type domainNode struct {
	children map[string]*domainNode
	suffix   ruleEntry // best DOMAIN-SUFFIX rule ending at this node
	exact    ruleEntry // best DOMAIN rule ending at this node
}

func newDomainNode() *domainNode {
	return &domainNode{children: make(map[string]*domainNode)}
}

// keywordRule is a substring rule. Keywords are not label aligned, so they
// are kept in a flat slice and scanned during Match.
type keywordRule struct {
	keyword string
	entry   ruleEntry
}

// DomainTrie indexes DOMAIN, DOMAIN-SUFFIX and DOMAIN-KEYWORD rules.
//
// Domains are inserted with their labels reversed (e.g. "com.google.www"),
// so matching walks at most one node per domain label: O(number of labels).
type DomainTrie struct {
	mu       sync.RWMutex
	root     *domainNode
	keywords []keywordRule
}

// NewDomainTrie returns an empty, ready-to-use DomainTrie.
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{root: newDomainNode()}
}

// Insert adds a DOMAIN-SUFFIX rule. The suffix matches the domain itself and
// any of its subdomains (e.g. "google.com" matches "www.google.com").
func (t *DomainTrie) Insert(suffix string, priority int, adapter string) {
	t.insert(suffix, priority, adapter, false)
}

// InsertExact adds a DOMAIN rule that matches only the exact host.
func (t *DomainTrie) InsertExact(domain string, priority int, adapter string) {
	t.insert(domain, priority, adapter, true)
}

// InsertKeyword adds a DOMAIN-KEYWORD rule that matches any host containing
// the keyword as a substring.
func (t *DomainTrie) InsertKeyword(keyword string, priority int, adapter string) {
	kw := normalizeHost(keyword)
	if kw == "" {
		return
	}
	t.mu.Lock()
	t.keywords = append(t.keywords, keywordRule{
		keyword: kw,
		entry:   ruleEntry{adapter: adapter, priority: priority, set: true},
	})
	t.mu.Unlock()
}

func (t *DomainTrie) insert(domain string, priority int, adapter string, exact bool) {
	labels := reverseLabels(domain)
	if len(labels) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.root
	for _, label := range labels {
		child := n.children[label]
		if child == nil {
			child = newDomainNode()
			n.children[label] = child
		}
		n = child
	}
	slot := &n.suffix
	if exact {
		slot = &n.exact
	}
	if betterPriority(priority, *slot) {
		*slot = ruleEntry{adapter: adapter, priority: priority, set: true}
	}
}

// Match returns the highest-priority (smallest priority value) rule matching
// host. Exact, suffix and keyword candidates all compete on priority.
func (t *DomainTrie) Match(host string) (adapter string, priority int, ok bool) {
	host = normalizeHost(host)
	t.mu.RLock()
	defer t.mu.RUnlock()

	var best ruleEntry
	consider := func(e ruleEntry) {
		if e.set && betterPriority(e.priority, best) {
			best = e
		}
	}

	for _, k := range t.keywords {
		if k.keyword != "" && strings.Contains(host, k.keyword) {
			consider(k.entry)
		}
	}

	n := t.root
	for _, label := range reverseLabels(host) {
		child := n.children[label]
		if child == nil {
			// No deeper suffix/exact rule can match; keyword candidates
			// gathered so far are the only possible matches.
			if best.set {
				return best.adapter, best.priority, true
			}
			return "", 0, false
		}
		n = child
		consider(n.suffix)
	}
	// Only an exact rule at the very last node can match the whole host.
	consider(n.exact)

	if best.set {
		return best.adapter, best.priority, true
	}
	return "", 0, false
}

// normalizeHost lowercases the host and removes a leading/trailing dot.
func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, ".")
	return s
}

// reverseLabels splits a domain on "." and returns its labels in reverse
// order, skipping empty labels produced by stray dots.
func reverseLabels(s string) []string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
