package ruleindex

import (
	"net/netip"
	"sync"
)

// ipEntry is the rule stored at a prefix node. A smaller priority wins when
// several rules are inserted for the same prefix.
type ipEntry struct {
	adapter  string
	priority int
	set      bool
}

// ipNode is a binary trie node: child[0] is a 0 bit, child[1] a 1 bit.
type ipNode struct {
	child [2]*ipNode
	entry ipEntry
}

// IPTree is a binary prefix trie supporting IPv4 and IPv6 longest-prefix
// matching. IPv4 and IPv6 live in separate trees so bit widths never mix.
type IPTree struct {
	mu sync.RWMutex
	v4 *ipNode
	v6 *ipNode
}

// NewIPTree returns an empty, ready-to-use IPTree.
func NewIPTree() *IPTree {
	return &IPTree{v4: &ipNode{}, v6: &ipNode{}}
}

// Insert adds a CIDR rule. Host bits in prefix are masked off. If a rule for
// the same prefix already exists, the one with the smaller priority wins.
func (t *IPTree) Insert(prefix netip.Prefix, priority int, adapter string) {
	if !prefix.IsValid() {
		return
	}
	addr := prefix.Addr().Unmap()
	if !addr.IsValid() {
		return
	}

	maxBits := 128
	if addr.Is4() {
		maxBits = 32
	}
	bits := prefix.Bits()
	if bits < 0 {
		bits = 0
	}
	if bits > maxBits {
		bits = maxBits
	}
	p := netip.PrefixFrom(addr, bits).Masked()

	root := t.v6
	if addr.Is4() {
		root = t.v4
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	n := root
	for i := 0; i < bits; i++ {
		b := addrBit(p.Addr(), i)
		if n.child[b] == nil {
			n.child[b] = &ipNode{}
		}
		n = n.child[b]
	}
	if !n.entry.set || priority < n.entry.priority {
		n.entry = ipEntry{adapter: adapter, priority: priority, set: true}
	}
}

// Match returns the rule with the longest matching prefix for ip. When two
// rules share the same prefix, the smaller priority wins (resolved at insert).
func (t *IPTree) Match(ip netip.Addr) (adapter string, priority int, ok bool) {
	if !ip.IsValid() {
		return "", 0, false
	}
	ip = ip.Unmap()

	root := t.v6
	maxBits := 128
	if ip.Is4() {
		root = t.v4
		maxBits = 32
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	n := root
	var best ipEntry
	if n.entry.set {
		best = n.entry // a /0 default route
	}
	for i := 0; i < maxBits; i++ {
		n = n.child[addrBit(ip, i)]
		if n == nil {
			break
		}
		if n.entry.set {
			// Going deeper means a longer prefix, which always wins.
			best = n.entry
		}
	}
	if best.set {
		return best.adapter, best.priority, true
	}
	return "", 0, false
}

// addrBit returns bit i (counting from the most significant bit) of addr.
func addrBit(addr netip.Addr, i int) byte {
	var b byte
	if addr.Is4() {
		v := addr.As4()
		b = v[i>>3]
	} else {
		v := addr.As16()
		b = v[i>>3]
	}
	if b&(byte(1)<<(7-uint(i&7))) != 0 {
		return 1
	}
	return 0
}
