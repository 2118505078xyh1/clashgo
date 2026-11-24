// Package batch coalesces high-frequency updates into periodic flushes,
// reducing UI repaints. Inspired by a reference GUI/a reference client event batching.
package batch

import (
	"sync"
	"time"
)

// Coalescer buffers the latest value and flushes it at most once per interval.
type Coalescer struct {
	mu       sync.Mutex
	interval time.Duration
	latest   any
	dirty    bool
	sink     func(any)
	stop     chan struct{}
	done     chan struct{}
}

// New creates a coalescer that calls sink at most once per interval.
func New(interval time.Duration, sink func(any)) *Coalescer {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	c := &Coalescer{
		interval: interval, sink: sink,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go c.loop()
	return c
}

// Submit records the latest value; only the most recent is flushed.
func (c *Coalescer) Submit(v any) {
	c.mu.Lock()
	c.latest = v
	c.dirty = true
	c.mu.Unlock()
}

func (c *Coalescer) loop() {
	defer close(c.done)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.flush()
		}
	}
}

func (c *Coalescer) flush() {
	c.mu.Lock()
	if !c.dirty {
		c.mu.Unlock()
		return
	}
	v := c.latest
	c.dirty = false
	c.mu.Unlock()
	c.sink(v)
}

// Stop flushes pending work and stops the loop.
func (c *Coalescer) Stop() {
	close(c.stop)
	<-c.done
	c.flush()
}
