package safemode

import (
	"errors"
	"strings"
	"sync"
)

// ErrReadOnly is returned when a mutating operation is attempted while the
// application is in read-only mode.
var ErrReadOnly = errors.New("read-only mode: operation denied")

// ACL is a small, concurrency-safe gate shared by the UI and the backend
// services. ReadOnly is exported so a zero-value ACL can be configured
// directly; use SetReadOnly/IsReadOnly when it is shared across goroutines.
type ACL struct {
	ReadOnly bool

	mu sync.RWMutex
}

// SetReadOnly enables or disables read-only mode.
func (a *ACL) SetReadOnly(v bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.ReadOnly = v
	a.mu.Unlock()
}

// IsReadOnly reports whether writes are currently refused.
func (a *ACL) IsReadOnly() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	v := a.ReadOnly
	a.mu.RUnlock()
	return v
}

// Guard runs fn only when writes are permitted. In read-only mode it returns
// ErrReadOnly without calling fn, so the caller's mutation never happens.
func (a *ACL) Guard(fn func() error) error {
	if fn == nil {
		return nil
	}
	if a.IsReadOnly() {
		return ErrReadOnly
	}
	return fn()
}

// CheckPermission rejects write-style operations ("write:profile",
// "write:settings", "write:proxy", ...) while read-only mode is active.
// Read operations and a nil ACL are always allowed.
func CheckPermission(acl *ACL, op string) error {
	if acl == nil || !acl.IsReadOnly() {
		return nil
	}
	if op == "write" || strings.HasPrefix(op, "write:") {
		return ErrReadOnly
	}
	return nil
}
