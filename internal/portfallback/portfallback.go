// Package portfallback implements session-only mixed-port fallback: when the
// desired port is occupied, pick the next available port for this session
// only, without persisting it (so next launch retries the user's port).
package portfallback

import (
	"fmt"
	"net"
	"sync"
)

// Resolver finds an available port, skipping reserved ports.
type Resolver struct {
	mu       sync.Mutex
	reserved map[int]bool
}

// New creates a resolver with a set of reserved ports (other listeners,
// external-controller, etc.) that must never be chosen as fallback.
func New(reserved ...int) *Resolver {
	m := map[int]bool{}
	for _, p := range reserved {
		m[p] = true
	}
	return &Resolver{reserved: m}
}

// Available reports whether a TCP port can be bound on loopback.
func (r *Resolver) Available(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// Resolve returns the desired port if free, otherwise the next available
// port (from desired+1 upward, then wrapping to 1025). Returns
// (port, changed) — changed is true when a fallback was chosen.
func (r *Resolver) Resolve(desired int) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Available(desired) && !r.reserved[desired] {
		return desired, false
	}
	for p := desired + 1; p <= 65535; p++ {
		if r.reserved[p] {
			continue
		}
		if r.Available(p) {
			return p, true
		}
	}
	for p := 1025; p < desired; p++ {
		if r.reserved[p] {
			continue
		}
		if r.Available(p) {
			return p, true
		}
	}
	return desired, false // give up; let the core report the error
}
