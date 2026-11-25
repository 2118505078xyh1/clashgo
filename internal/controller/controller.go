// Package controller talks to 自研内核's embedded REST API (external controller)
// and its WebSocket streams for live traffic, logs and connections.
package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"clashgo/internal/config"
)

// Client is a thin wrapper around 自研内核's REST API.
type Client struct {
	Base   string
	Secret string
	HTTP   *http.Client
}

// New creates a REST client.
func New(base, secret string) *Client {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return &Client{
		Base:   base,
		Secret: secret,
		HTTP:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) newRequest(method, path string, body any) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.Base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	return req, nil
}

func (c *Client) do(method, path string, body, out any) error {
	req, err := c.newRequest(method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("内核 API %s %s: HTTP %d: %s", method, path, resp.StatusCode, string(b))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Stats 返回内核累计流量（上传/下载/活跃连接数）。
// Stats returns the cumulative traffic counters.
//
// mihomo exposes the totals on /connections (downloadTotal / uploadTotal),
// not on a separate /stats endpoint — the old /stats path returns 404 and the
// counters stayed at zero.
func (c *Client) Stats() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/connections", nil, &out)
	if err != nil {
		return nil, err
	}
	// 统一成 upload / download 两个键，兼容自研内核的命名。
	stats := map[string]any{}
	if v, ok := out["uploadTotal"]; ok {
		stats["upload"] = v
	}
	if v, ok := out["downloadTotal"]; ok {
		stats["download"] = v
	}
	return stats, nil
}

// TrafficTotal 返回内核当前的累计上传/下载字节数。
//
// 直接读绝对值，不依赖 WebSocket：/traffic 的推送在桌面客户端里不可靠
// （连接能建立但收不到帧），而累计值始终准确，差分就能算出速率。
func (c *Client) TrafficTotal() (up, down int64, err error) {
	stats, err := c.Stats()
	if err != nil {
		return 0, 0, err
	}
	if v, ok := stats["upload"].(float64); ok {
		up = int64(v)
	}
	if v, ok := stats["download"].(float64); ok {
		down = int64(v)
	}
	return up, down, nil
}

// Version returns core version info.
func (c *Client) Version() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/version", nil, &out)
	return out, err
}

// Configs returns the current base config.
func (c *Client) Configs() (map[string]any, error) {
	var out map[string]any
	err := c.do(http.MethodGet, "/configs", nil, &out)
	return out, err
}

// Proxies returns all proxy adapters and groups.
func (c *Client) Proxies() (map[string]config.ProxyView, error) {
	var raw struct {
		Proxies map[string]struct {
			Type    string   `json:"type"`
			Now     string   `json:"now"`
			All     []string `json:"all"`
			History []struct {
				Time  string `json:"time"`
				Delay int    `json:"delay"`
			} `json:"history"`
			UDP bool `json:"udp"`
		} `json:"proxies"`
	}
	if err := c.do(http.MethodGet, "/proxies", nil, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]config.ProxyView, len(raw.Proxies))
	for name, p := range raw.Proxies {
		v := config.ProxyView{
			Name: name, Type: p.Type, Now: p.Now, All: p.All, UDP: p.UDP,
			Group: len(p.All) > 0,
		}
		for _, h := range p.History {
			v.History = append(v.History, config.DelayHistory{Time: h.Time, Delay: h.Delay})
		}
		out[name] = v
	}
	return out, nil
}

// Rules returns the active rule list.
func (c *Client) Rules() ([]map[string]any, error) {
	var out struct {
		Rules []map[string]any `json:"rules"`
	}
	err := c.do(http.MethodGet, "/rules", nil, &out)
	return out.Rules, err
}

// Connections returns active connections.
func (c *Client) Connections() ([]config.ConnectionView, error) {
	var out struct {
		Connections []config.ConnectionView `json:"connections"`
	}
	err := c.do(http.MethodGet, "/connections", nil, &out)
	return out.Connections, err
}

// CloseConnection closes a single connection by id.
func (c *Client) CloseConnection(id string) error {
	return c.do(http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

// CloseAllConnections closes every active connection.
func (c *Client) CloseAllConnections() error {
	return c.do(http.MethodDelete, "/connections", nil, nil)
}

// SetMode changes the proxy mode.
func (c *Client) SetMode(mode string) error {
	return c.do(http.MethodPatch, "/configs", map[string]any{"mode": mode}, nil)
}

// SelectNode chooses a node inside a proxy group.
func (c *Client) SelectNode(group, name string) error {
	return c.do(http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": name}, nil)
}

// Delay tests a proxy's latency, returning milliseconds (-1 on failure).
func (c *Client) Delay(name, testURL string, timeout int) (int, error) {
	path := fmt.Sprintf("/proxies/%s/delay?url=%s&timeout=%d",
		url.PathEscape(name), url.QueryEscape(testURL), timeout)
	var raw struct {
		Delay int `json:"delay"`
	}
	err := c.do(http.MethodGet, path, nil, &raw)
	return raw.Delay, err
}

// GroupDelay tests all nodes in a group concurrently.
func (c *Client) GroupDelay(group, testURL string, timeout int) (map[string]int, error) {
	path := fmt.Sprintf("/group/%s/delay?url=%s&timeout=%d",
		url.PathEscape(group), url.QueryEscape(testURL), timeout)
	var out map[string]int
	err := c.do(http.MethodGet, path, nil, &out)
	return out, err
}

// ReloadConfig forces 自研内核 to reload a config file.
func (c *Client) ReloadConfig(path string) error {
	q := url.QueryEscape(path)
	return c.do(http.MethodPut, "/configs?force=true&path="+q, nil, nil)
}

// DNSQuery performs an active DNS query through the core's /dns/query.
func (c *Client) DNSQuery(name, qtype string) (*DNSResponse, error) {
	if qtype == "" {
		qtype = "A"
	}
	path := "/dns/query?name=" + url.QueryEscape(name) + "&type=" + url.QueryEscape(qtype)
	var out DNSResponse
	err := c.do(http.MethodGet, path, nil, &out)
	return &out, err
}

// DNSResponse is the result of a DNS query. 自研内核 returns Question/Answer as
// arrays of objects ({name, type, data, TTL}), so we keep them raw and offer
// helpers; older/simpler resolvers may return plain strings.
type DNSResponse struct {
	Status   int               `json:"Status"`
	Question []json.RawMessage `json:"Question"`
	Answer   []json.RawMessage `json:"Answer"`
}

// AnswerStrings returns the "data" (or raw string) of each answer record.
func (d *DNSResponse) AnswerStrings() []string {
	out := make([]string, 0, len(d.Answer))
	for _, raw := range d.Answer {
		var obj struct {
			Data string `json:"data"`
		}
		if json.Unmarshal(raw, &obj) == nil && obj.Data != "" {
			out = append(out, obj.Data)
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// TrafficSample is one websocket traffic frame.
type TrafficSample struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// LogFrame is one websocket log frame.
type LogFrame struct {
	Type    string `json:"type"`
	Time    string `json:"time"`
	Payload string `json:"payload"`
}

// ConnectionFrame is a websocket /connections snapshot.
type ConnectionFrame struct {
	Connections []config.ConnectionView `json:"connections"`
}
