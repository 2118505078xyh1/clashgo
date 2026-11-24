package controller

import (
	"context"
	"sync"
	"time"
)

// DelayResult holds a per-node latency test result.
type DelayResult struct {
	Name  string
	Delay int // -1 = failed
}

// DelayOptions configures a batch delay test.
type DelayOptions struct {
	URL         string
	Timeout     int // milliseconds, per attempt
	Retries     int // number of attempts; best (min) is kept
	Concurrency int
}

// TestNodes tests each node individually with retries, keeping the minimum
// successful delay (idea from common practice, min wins;
// failed batches are retried with lower concurrency).
func (c *Client) TestNodes(ctx context.Context, nodes []string, opts DelayOptions) []DelayResult {
	if opts.Retries < 1 {
		opts.Retries = 1
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 4
	}
	results := make([]DelayResult, len(nodes))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, name := range nodes {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			best := -1
			for attempt := 0; attempt < opts.Retries; attempt++ {
				select {
				case <-ctx.Done():
					break
				default:
				}
				d, err := c.Delay(name, opts.URL, opts.Timeout)
				if err == nil && d > 0 {
					if best < 0 || d < best {
						best = d
					}
				}
				if best >= 0 && attempt >= 1 {
					break // two successful samples are enough
				}
				time.Sleep(50 * time.Millisecond)
			}
			results[i] = DelayResult{Name: name, Delay: best}
		}(i, name)
	}
	wg.Wait()
	return results
}
