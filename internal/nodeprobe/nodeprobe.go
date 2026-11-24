// Package nodeprobe probes each proxy node's exit IP by temporarily selecting
// it in its group, querying an IP-info service through the mixed proxy, then
// restoring the original selection. Results are cached to disk with a TTL.
package nodeprobe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"clashgo/internal/ipinfo"
)

// Result is one node's probe result.
type Result struct {
	Node        string `json:"node"`
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	OK          bool   `json:"ok"`
}

// Cache is the persisted probe results.
type Cache struct {
	Updated map[string]time.Time `json:"updated"`
	Results map[string]Result    `json:"results"`
}

// Store loads/saves the cache to a JSON file.
type Store struct {
	mu   sync.Mutex
	path string
	data Cache
}

// NewStore opens a cache file.
func NewStore(dataDir string) *Store {
	s := &Store{path: filepath.Join(dataDir, "node-ip-cache.json")}
	s.data.Updated = map[string]time.Time{}
	s.data.Results = map[string]Result{}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	if s.data.Updated == nil {
		s.data.Updated = map[string]time.Time{}
	}
	if s.data.Results == nil {
		s.data.Results = map[string]Result{}
	}
	return s
}

// Get returns a cached result if fresh enough.
func (s *Store) Get(node string, ttl time.Duration) (Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Results[node]
	if !ok {
		return Result{}, false
	}
	if t, ok := s.data.Updated[node]; ok && time.Since(t) < ttl {
		return r, true
	}
	return Result{}, false
}

// Put stores a result and persists the cache.
func (s *Store) Put(node string, r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Results[node] = r
	s.data.Updated[node] = time.Now()
	b, _ := json.MarshalIndent(s.data, "", "  ")
	_ = os.WriteFile(s.path, b, 0o644)
}

// Selector abstracts node selection (avoids import cycle with controller).
type Selector interface {
	SelectNode(group, name string) error
}

// Prober probes nodes one by one, restoring the original selection.
type Prober struct {
	selector Selector
	prober   *ipinfo.Prober
	store    *Store
	onResult func(Result)
}

// New creates a node prober.
func New(sel Selector, mixedPort int, store *Store, onResult func(Result)) *Prober {
	return &Prober{
		selector: sel,
		prober:   ipinfo.New(mixedPort),
		store:    store,
		onResult: onResult,
	}
}

// ProbeGroup probes all nodes in a group sequentially, then restores the
// original selection. Cached results (24h) are returned without probing.
func (p *Prober) ProbeGroup(ctx context.Context, group, original string, nodes []string) []Result {
	// Restore the user's original node when we're done (or cancelled).
	defer func() {
		if original != "" {
			_ = p.selector.SelectNode(group, original)
		}
	}()
	results := make([]Result, 0, len(nodes))
	for _, node := range nodes {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		if cached, ok := p.store.Get(node, 24*time.Hour); ok {
			results = append(results, cached)
			if p.onResult != nil {
				p.onResult(cached)
			}
			continue
		}
		// Switch to this node, probing uses the live mixed port.
		if err := p.selector.SelectNode(group, node); err != nil {
			results = append(results, Result{Node: node, OK: false})
			continue
		}
		time.Sleep(300 * time.Millisecond) // let the proxy settle
		info, err := p.prober.Probe(ctx)
		var r Result
		if err != nil {
			r = Result{Node: node, OK: false}
		} else {
			r = Result{Node: node, IP: info.IP, CountryCode: info.CountryCode, Country: info.Country, OK: true}
			p.prober.Invalidate()
		}
		p.store.Put(node, r)
		results = append(results, r)
		if p.onResult != nil {
			p.onResult(r)
		}
		time.Sleep(200 * time.Millisecond) // rate-limit free IP APIs
	}
	_ = original
	return results
}
