// Package ipinfo probes the proxy's exit IP and geolocation through the local
// mixed proxy, with a cache so rapid node switches don't spam requests.
package ipinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Info is the exit IP information.
type Info struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	QueryTime   string `json:"query_time"`
}

// Candidate IP-info endpoints (tried in order, failover on error). The list
// covers the formats used by ip-api, ip.sb, ipapi.is and internetdata.io.
var DefaultEndpoints = []string{
	"http://ip-api.com/json/?fields=status,query,country,countryCode,city,isp",
	"https://api.ip.sb/geoip",
	"https://api.ipapi.is",
	"https://api.internetdata.io/myip",
}

// Prober queries exit IP through the proxy.
type Prober struct {
	mu       sync.Mutex
	proxyURL string
	cache    *Info
	cachedAt time.Time
	client   *http.Client
}

// New creates a prober using the mixed port.
func New(mixedPort int) *Prober {
	pu := fmt.Sprintf("http://127.0.0.1:%d", mixedPort)
	proxyURL, _ := url.Parse(pu)
	return &Prober{
		proxyURL: pu,
		client: &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   10 * time.Second,
		},
	}
}

// Invalidate clears the cache (call after switching nodes).
func (p *Prober) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = nil
}

// Parse parses an IP-info JSON response from various providers, handling the
// field-name differences (ip/clientIp/ip_addr/query; country_code/countryCode/...).
func Parse(body []byte) (*Info, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
		return ""
	}
	ip := get("ip", "clientIp", "client_ip", "ip_addr", "query")
	cc := get("country_code", "countryCode", "country_code", "cc")
	country := get("country", "country_name", "countryName")
	if loc, ok := raw["location"].(map[string]any); ok {
		if cc == "" {
			if v, ok := loc["country_code"].(string); ok {
				cc = v
			} else if v, ok := loc["country"].(string); ok {
				cc = v
			}
		}
		if country == "" {
			if v, ok := loc["country"].(string); ok {
				country = v
			}
		}
	}
	if ip == "" {
		return nil, fmt.Errorf("no IP field in response")
	}
	if cc == "" {
		cc = "unknown"
	}
	return &Info{
		IP: ip, CountryCode: strings.ToUpper(cc), Country: country,
		City: get("city"), ISP: get("isp", "org", "asn_organization"),
		QueryTime: time.Now().Format("15:04:05"),
	}, nil
}

// Probe fetches exit IP info, using a 5-minute cache and failover endpoints.
func (p *Prober) Probe(ctx context.Context) (*Info, error) {
	p.mu.Lock()
	if p.cache != nil && time.Since(p.cachedAt) < 5*time.Minute {
		info := *p.cache
		p.mu.Unlock()
		return &info, nil
	}
	p.mu.Unlock()

	var lastErr error
	for _, endpoint := range DefaultEndpoints {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		info, err := Parse(body)
		if err != nil {
			lastErr = err
			continue
		}
		p.mu.Lock()
		p.cache, p.cachedAt = info, time.Now()
		p.mu.Unlock()
		return info, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all IP endpoints failed")
	}
	return nil, lastErr
}
