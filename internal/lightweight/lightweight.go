// Package lightweight implements automatic idle suspension of the proxy
// core (a reference GUI's lightweight mode).
package lightweight

import (
	"sync"
	"time"
)

// Controller tracks activity and decides when to suspend.
type Controller struct {
	mu         sync.Mutex
	enabled    bool
	idleAfter  time.Duration
	lastActive time.Time
	suspended  bool
	onSuspend  func()
	onResume   func()
}

// New creates a controller with the given idle timeout in minutes.
func New(minutes int, onSuspend, onResume func()) *Controller {
	if minutes < 1 {
		minutes = 10
	}
	return &Controller{
		idleAfter:  time.Duration(minutes) * time.Minute,
		lastActive: time.Now(),
		onSuspend:  onSuspend,
		onResume:   onResume,
	}
}

// SetEnabled enables or disables idle tracking.
func (c *Controller) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
	if !enabled && c.suspended {
		c.resumeLocked()
	}
}

// Activity records network activity, resuming a suspended core.
func (c *Controller) Activity() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastActive = time.Now()
	if c.suspended {
		c.resumeLocked()
	}
}

// Tick checks whether the idle timeout has elapsed.
func (c *Controller) Tick() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || c.suspended {
		return
	}
	if time.Since(c.lastActive) >= c.idleAfter {
		c.suspended = true
		if c.onSuspend != nil {
			go c.onSuspend()
		}
	}
}

// Suspended reports whether the core is suspended.
func (c *Controller) Suspended() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.suspended
}

func (c *Controller) resumeLocked() {
	c.suspended = false
	if c.onResume != nil {
		go c.onResume()
	}
}
