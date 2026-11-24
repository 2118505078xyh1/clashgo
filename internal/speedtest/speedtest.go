// Package speedtest implements a full node speedtest suite: TCP ping,
// real HTTP latency through the proxy, and download throughput measurement.
// Inspired by a reference client's SpeedtestService.
package speedtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Result holds all measurements for one node.
type Result struct {
	Node         string
	TCPPing      int64   // milliseconds, -1 = failed
	RealLatency  int     // milliseconds via proxy, -1 = failed
	DownloadKbps float64 // kilobytes per second
	OK           bool
}

// Options configures the speedtest.
type Options struct {
	TCPHost       string // host for TCP ping (uses node's own server if empty)
	TCPPort       string
	LatencyURL    string
	DownloadURL   string
	Timeout       time.Duration
	DownloadBytes int64 // total bytes to download
	Retries       int
	Concurrency   int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		LatencyURL:    "https://www.gstatic.com/generate_204",
		DownloadURL:   "https://speed.cloudflare.com/__down?bytes=10000000",
		Timeout:       5 * time.Second,
		DownloadBytes: 5 * 1024 * 1024,
		Retries:       2,
		Concurrency:   4,
	}
}

// TCPPing measures a raw TCP connect time to host:port.
func TCPPing(ctx context.Context, host, port string, timeout time.Duration) int64 {
	if host == "" || port == "" {
		return -1
	}
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds()
}

// MeasureAll runs all three measurements for one node through the given
// HTTP clients: directClient for TCP (no proxy needed is handled by caller),
// proxyClient for latency/download (already configured with the node proxy).
func MeasureAll(ctx context.Context, node, tcpHost, tcpPort string, proxyClient *http.Client, opts Options) Result {
	r := Result{Node: node}
	// 1. TCP ping (raw socket, best-effort)
	r.TCPPing = TCPPing(ctx, tcpHost, tcpPort, opts.Timeout)

	// 2. Real latency through proxy (2 samples, min wins)
	r.RealLatency = -1
	for i := 0; i < opts.Retries; i++ {
		lat := measureLatency(ctx, proxyClient, opts.LatencyURL, opts.Timeout)
		if lat >= 0 && (r.RealLatency < 0 || lat < r.RealLatency) {
			r.RealLatency = lat
		}
	}

	// 3. Download throughput
	r.DownloadKbps = measureDownload(ctx, proxyClient, opts.DownloadURL, opts.DownloadBytes, opts.Timeout)

	r.OK = r.TCPPing >= 0 || r.RealLatency >= 0 || r.DownloadKbps > 0
	return r
}

func measureLatency(ctx context.Context, client *http.Client, url string, timeout time.Duration) int {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(c, http.MethodHead, url, nil)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	_ = resp.Body.Close()
	return int(time.Since(start).Milliseconds())
}

func measureDownload(ctx context.Context, client *http.Client, url string, limit int64, timeout time.Duration) float64 {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	n, err := io.CopyN(io.Discard, resp.Body, limit)
	if err != nil && n == 0 {
		return 0
	}
	secs := time.Since(start).Seconds()
	if secs <= 0 {
		return 0
	}
	return float64(n) / secs / 1024
}

// Batch runs speedtests for multiple nodes with a concurrency limit and
// streams results as they complete. Results are returned in completion order.
func Batch(ctx context.Context, nodes []NodeTarget, client *http.Client, opts Options, onResult func(Result)) []Result {
	if opts.Concurrency < 1 {
		opts.Concurrency = 4
	}
	sem := make(chan struct{}, opts.Concurrency)
	var mu sync.Mutex
	var results []Result
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(n NodeTarget) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			res := MeasureAll(ctx, n.Name, n.TCPHost, n.TCPPort, client, opts)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
			if onResult != nil {
				onResult(res)
			}
		}(node)
	}
	wg.Wait()
	return results
}

// NodeTarget describes a node to test.
type NodeTarget struct {
	Name    string
	TCPHost string
	TCPPort string
}

func (r Result) String() string {
	return fmt.Sprintf("%s: tcp=%dms real=%dms down=%.0fKB/s",
		r.Node, r.TCPPing, r.RealLatency, r.DownloadKbps)
}
