package ui

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"clashgo/internal/speedtest"
)

// runFullSpeedtest performs TCP ping + real latency + download speed for every
// node in a group, selecting each node first, then restoring the original.
func (a *App) runFullSpeedtest(group string, nodes []string, original string) {
	a.SpeedMu.Lock()
	if a.SpeedTestBusy {
		a.SpeedMu.Unlock()
		return
	}
	a.SpeedTestBusy = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	a.SpeedCancel = cancel
	a.SpeedMu.Unlock()

	go func() {
		defer func() {
			cancel()
			if original != "" {
				_ = a.currentClient().SelectNode(group, original)
			}
			a.win.Update(func() { a.SpeedMu.Lock(); a.SpeedTestBusy = false; a.SpeedMu.Unlock() })
		}()

		port := a.Settings.MixedPort
		if a.effectivePort > 0 {
			port = a.effectivePort
		}
		pu, _ := url.Parse("http://127.0.0.1:" + itoaLocal(port))
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 30 * time.Second}
		opts := speedtest.DefaultOptions()
		opts.LatencyURL = a.Settings.LatencyTestURL
		opts.Timeout = time.Duration(a.Settings.LatencyTimeout) * time.Millisecond
		if opts.Timeout <= 0 {
			opts.Timeout = 5 * time.Second
		}

		for _, node := range nodes {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// Select this node so the mixed port routes through it.
			if err := a.currentClient().SelectNode(group, node); err != nil {
				continue
			}
			time.Sleep(200 * time.Millisecond)

			// Try to get the node's server for TCP ping from proxy detail is
			// not directly exposed; skip TCP host (real latency still measured).
			res := speedtest.MeasureAll(ctx, node, "", "", client, opts)
			a.win.Update(func() { a.SpeedResults[node] = res })
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

func (a *App) cancelSpeedtest() {
	a.SpeedMu.Lock()
	cancel := a.SpeedCancel
	a.SpeedMu.Unlock()
	if cancel != nil {
		cancel()
	}
}
