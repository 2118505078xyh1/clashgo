// Package guard keeps the system proxy pointed at clashgo. Some applications
// (and Windows itself) reset proxy settings; the guard detects drift and
// re-applies the expected configuration.
package guard

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Applier is the interface the guard uses to read and write the system proxy.
type Applier interface {
	Get() (enable bool, server string, bypass string, err error)
	Set(enable bool, server, bypass string) error
}

// Guard periodically verifies and restores the system proxy.
type Guard struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	applier    Applier
	server     string
	bypass     string
	interval   time.Duration
	failures   int
	maxFail    int
	onFail     func(reason string)
	generation uint64
}

// New creates a guard. Call Start to begin monitoring.
func New(applier Applier, server, bypass string, intervalSec int, onFail func(string)) *Guard {
	if intervalSec < 1 {
		intervalSec = 30
	}
	return &Guard{
		applier:  applier,
		server:   server,
		bypass:   bypass,
		interval: time.Duration(intervalSec) * time.Second,
		maxFail:  3,
		onFail:   onFail,
	}
}

// Start begins guarding in a background goroutine. Calling Start again
// replaces the previous guard.
func (g *Guard) Start() {
	g.mu.Lock()
	if g.cancel != nil {
		g.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel
	g.failures = 0
	g.generation++
	gen := g.generation
	g.mu.Unlock()

	go g.loop(ctx, gen)
}

// Stop halts the guard.
func (g *Guard) Stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
}

func (g *Guard) loop(ctx context.Context, gen uint64) {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.check(ctx, gen)
		}
	}
}

func (g *Guard) check(ctx context.Context, gen uint64) {
	g.mu.Lock()
	if gen != g.generation {
		g.mu.Unlock()
		return // superseded guard
	}
	g.mu.Unlock()
	enable, server, _, err := g.applier.Get()
	if err == nil && enable && normalizeServer(server) == normalizeServer(g.server) {
		// Still pointing at us — clear failure streak.
		g.mu.Lock()
		g.failures = 0
		g.mu.Unlock()
		return
	}
	// Drifted (or read failed) — re-apply, but only if still the current guard.
	g.mu.Lock()
	if gen != g.generation {
		g.mu.Unlock()
		return
	}
	g.mu.Unlock()
	if err := g.applier.Set(true, g.server, g.bypass); err != nil {
		g.mu.Lock()
		g.failures++
		stop := g.failures >= g.maxFail
		g.mu.Unlock()
		if stop {
			if g.onFail != nil {
				g.onFail("系统代理守卫连续失败 " + itoa(g.failures) + " 次已停止：" + err.Error())
			}
			g.Stop()
		}
		return
	}
	g.mu.Lock()
	g.failures = 0
	g.mu.Unlock()
}

func normalizeServer(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	// Registry may store "127.0.0.1:7897" or "http=...;https=..." etc.
	if i := strings.Index(s, "http="); i >= 0 {
		s = s[i+5:]
		if j := strings.IndexAny(s, "; "); j >= 0 {
			s = s[:j]
		}
	}
	return strings.TrimPrefix(s, "http://")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
