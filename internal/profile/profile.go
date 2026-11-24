// Package profile manages subscription profiles: import, refresh, switch.
package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clashgo/internal/yaml"

	"clashgo/internal/config"
	"clashgo/internal/paths"
)

// Spill thresholds for large subscription responses.
//
// Rather than holding an arbitrarily large HTTP response in memory, we stream
// it to a temporary file first. Responses smaller than spillThreshold are read
// back and decoded via the original in-memory path (fast, no extra syscalls
// that matter); larger ones are decoded from the file with a streaming base64
// decoder, so the raw response never occupies a contiguous []byte. Responses
// larger than spillMaxBytes are rejected to guard against runaway endpoints.
const (
	spillThreshold = 2 << 20  // 2 MiB: above this we decode from the temp file
	spillMaxBytes  = 50 << 20 // 50 MiB: hard cap on a subscription response
)

// Manager handles profile persistence and subscriptions.
type Manager struct {
	DB *config.ProfilesDB
}

// New loads profiles.yaml.
func New() (*Manager, error) {
	db, err := config.LoadProfiles(paths.ProfilesDB)
	if err != nil {
		return nil, err
	}
	return &Manager{DB: db}, nil
}

// Save persists profiles.yaml.
func (m *Manager) Save() error {
	return config.SaveProfiles(paths.ProfilesDB, m.DB)
}

func newUID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateLocal creates a profile from raw YAML content.
func (m *Manager) CreateLocal(name, yamlContent string) (*config.PrfItem, error) {
	if err := validateYAML([]byte(yamlContent)); err != nil {
		return nil, err
	}
	uid := newUID()
	file := uid + ".yaml"
	if err := os.WriteFile(filepath.Join(paths.Profiles, file), []byte(yamlContent), 0o644); err != nil {
		return nil, err
	}
	item := &config.PrfItem{
		UID: uid, Type: config.ProfileLocal, Name: name,
		File: file, Updated: time.Now().Unix(),
	}
	m.DB.Items = append(m.DB.Items, item)
	if m.DB.Current == "" {
		m.DB.Current = uid
	}
	return item, m.Save()
}

// buildFetchURL wraps a subscription URL through a conversion service if set.
// Supports a common style (base + path + ?url=) and a converter style
// (base + /sub?target=clash&url=).
func buildFetchURL(source, convertTarget string) string {
	ct := strings.TrimSpace(convertTarget)
	if ct == "" {
		return source
	}
	sep := "?"
	if strings.Contains(ct, "?") {
		sep = "&"
	}
	// Services that expose /sub/... or /api/... expect ?url=; others expect
	// ?target=clash&url=.
	if strings.Contains(strings.ToLower(ct), "/sub") || strings.Contains(ct, "/api/") {
		return ct + sep + "url=" + neturl.QueryEscape(source)
	}
	return ct + sep + "target=clash&url=" + neturl.QueryEscape(source)
}

// ImportRemote downloads a subscription URL and stores it as a profile.
// It delegates to ImportRemoteSpill so behavior is identical while large
// responses are spilled to disk instead of being fully buffered in memory.
func (m *Manager) ImportRemote(name, url string, opts *config.PrfOption) (*config.PrfItem, error) {
	return m.ImportRemoteSpill(name, url, opts)
}

// ImportRemoteSpill downloads a subscription through the shared fetch path,
// then stores the decoded Clash YAML as a new profile.
func (m *Manager) ImportRemoteSpill(name, url string, opts *config.PrfOption) (*config.PrfItem, error) {
	content, header, err := downloadSubscription(url, opts)
	if err != nil {
		return nil, err
	}

	uid := newUID()
	file := uid + ".yaml"
	if err := os.WriteFile(filepath.Join(paths.Profiles, file), content, 0o644); err != nil {
		return nil, err
	}
	item := &config.PrfItem{
		UID: uid, Type: config.ProfileRemote, Name: name,
		File: file, URL: url, Option: opts,
		Updated: time.Now().Unix(),
		Extra:   parseTrafficHeaders(header),
	}
	m.DB.Items = append(m.DB.Items, item)
	if m.DB.Current == "" {
		m.DB.Current = uid
	}
	return item, m.Save()
}

// downloadSubscription is the single fetch/decode/validate path used by both
// import and refresh. A subscription that returns an HTML challenge or a JSON
// error page must never replace a working profile: validation requires a real
// Clash YAML mapping with at least one recognised top-level key.
func downloadSubscription(url string, opts *config.PrfOption) ([]byte, http.Header, error) {
	fetchURL := url
	if opts != nil {
		fetchURL = buildFetchURL(url, opts.ConvertTarget)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	if opts != nil && opts.TimeoutSeconds > 0 {
		client.Timeout = time.Duration(opts.TimeoutSeconds) * time.Second
	}
	req, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, nil, err
	}
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	// 旧界面会把 clashgo/1.0 写进订阅选项，这个 UA 会被 Cloudflare 直接挡掉；
	// 只有看起来像浏览器的自定义 UA 才覆盖默认值。
	if opts != nil && strings.HasPrefix(strings.TrimSpace(opts.UserAgent), "Mozilla/") {
		ua = opts.UserAgent
	}
	req.Header.Set("User-Agent", ua)
	// 很多订阅服务在 Cloudflare 后面，只有请求像浏览器时才返回真正内容；
	// 不带 Accept 时即使 token 正确也会返回 403 HTML 挑战页。
	req.Header.Set("Accept", "text/yaml,application/yaml,application/x-yaml,text/plain,*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header, fmt.Errorf("subscription HTTP %d", resp.StatusCode)
	}

	// Stream the response to a temp file, reading at most the cap plus one
	// byte so an over-limit response is detected without buffering it all.
	tmp, err := os.CreateTemp("", "clashgo-sub-*")
	if err != nil {
		return nil, resp.Header, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // always clean up the spilled response

	written, copyErr := io.Copy(tmp, io.LimitReader(resp.Body, spillMaxBytes+1))
	closeErr := tmp.Close()
	if copyErr != nil {
		return nil, resp.Header, copyErr
	}
	if closeErr != nil {
		return nil, resp.Header, closeErr
	}
	if written > spillMaxBytes {
		return nil, resp.Header, fmt.Errorf("subscription response exceeds %d bytes limit", spillMaxBytes)
	}

	var content []byte
	if written < spillThreshold {
		body, readErr := os.ReadFile(tmpPath)
		if readErr != nil {
			return nil, resp.Header, readErr
		}
		content = decodeSubscription(body)
	} else {
		content, err = decodeSubscriptionFromFile(tmpPath)
		if err != nil {
			return nil, resp.Header, err
		}
	}

	if err := ValidateConfig(content); err != nil {
		// 有些服务返回的是 base64 编码的分享链接列表，而不是 Clash YAML。
		// 先转换成受支持的配置格式，再判定失败。
		if converted, convErr := ConvertShareLinks(content); convErr == nil {
			content = converted
		} else {
			return nil, resp.Header, fmt.Errorf("subscription is not a Clash config: %w", err)
		}
	}
	return content, resp.Header, nil
}

// Refresh re-downloads a remote profile. Validation happens before the
// on-disk profile is touched, so a failed refresh keeps the last good config.
func (m *Manager) Refresh(uid string) error {
	item := m.DB.Find(uid)
	if item == nil || item.Type != config.ProfileRemote {
		return fmt.Errorf("profile %s is not remote", uid)
	}
	content, header, err := downloadSubscription(item.URL, item.Option)
	if err != nil {
		return err
	}

	// Write to a temporary file in the same directory and rename it into
	// place, so a crash or a failed write cannot leave a truncated profile.
	dest := filepath.Join(paths.Profiles, item.File)
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".refresh-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return err
	}
	item.Extra = mergeTrafficHeaders(item.Extra, parseTrafficHeaders(header))
	item.Updated = time.Now().Unix()
	return m.Save()
}

func mergeTrafficHeaders(old, fresh *config.ProfileTraffic) *config.ProfileTraffic {
	if old == nil && fresh == nil {
		return nil
	}
	out := &config.ProfileTraffic{}
	if old != nil {
		*out = *old
	}
	if fresh != nil {
		if fresh.Upload != 0 {
			out.Upload = fresh.Upload
		}
		if fresh.Download != 0 {
			out.Download = fresh.Download
		}
		if fresh.Total != 0 {
			out.Total = fresh.Total
		}
		if fresh.Expire != 0 {
			out.Expire = fresh.Expire
		}
	}
	return out
}

// Delete removes a profile and its file.
func (m *Manager) Delete(uid string) error {
	idx := -1
	for i, item := range m.DB.Items {
		if item.UID == uid {
			idx = i
			_ = os.Remove(filepath.Join(paths.Profiles, item.File))
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("profile %s not found", uid)
	}
	m.DB.Items = append(m.DB.Items[:idx], m.DB.Items[idx+1:]...)
	if m.DB.Current == uid {
		m.DB.Current = ""
		if len(m.DB.Items) > 0 {
			m.DB.Current = m.DB.Items[0].UID
		}
	}
	return m.Save()
}

// Select switches the active profile.
func (m *Manager) Select(uid string) error {
	if m.DB.Find(uid) == nil {
		return fmt.Errorf("profile %s not found", uid)
	}
	m.DB.Current = uid
	return m.Save()
}

// Content returns the raw YAML of a profile.
func (m *Manager) Content(item *config.PrfItem) ([]byte, error) {
	return os.ReadFile(filepath.Join(paths.Profiles, item.File))
}

// SaveContent writes raw profile content and validates it according to the
// profile type. Script attachments are plain JS, not YAML.
func (m *Manager) SaveContent(item *config.PrfItem, content []byte) error {
	if err := validateProfileContent(item.Type, content); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(paths.Profiles, item.File), content, 0o644)
}

// RecordSelection remembers a user's node pick in a proxy group.
func (m *Manager) RecordSelection(uid, group, node string) error {
	item := m.DB.Find(uid)
	if item == nil {
		return nil
	}
	if item.Selected == nil {
		item.Selected = map[string]string{}
	}
	item.Selected[group] = node
	return m.Save()
}

// clashConfigKeys are the top-level keys accepted in a Clash-compatible
// config. Requiring at least one of them is what keeps an HTTP error page
// (which is often valid YAML, e.g. `{"message":"token is error"}`) from
// being saved as a usable profile.
var clashConfigKeys = map[string]bool{
	"allow-lan": true, "authentication": true, "bind-address": true,
	"clash-verge": true, "dns": true, "ebpf": true, "experimental": true,
	"external-controller": true, "external-controller-cors": true,
	"external-ui": true, "geodata-mode": true, "global-client-fingerprint": true,
	"hosts": true, "http-port": true, "interface-name": true, "ipv6": true,
	"listener": true, "log-level": true, "mixed-port": true, "mode": true,
	"mihomo": true, "ntp": true, "port": true, "profile": true,
	"proxy-groups": true, "proxy-providers": true, "proxies": true,
	"redir-port": true, "rule-providers": true, "rules": true,
	"secret": true, "socks-port": true, "sniffer": true, "tcp-concurrent": true,
	"tls": true, "tproxy-port": true, "tun": true, "unified-delay": true,
}

// ValidateConfig reports whether b is a Clash-compatible YAML config that the
// enhance pipeline and kernel can actually use.
func ValidateConfig(b []byte) error {
	m, err := decodeYAMLMap(b)
	if err != nil {
		return err
	}
	for k := range m {
		if clashConfigKeys[strings.ToLower(k)] {
			return nil
		}
	}
	return fmt.Errorf("no recognised Clash config keys at top level")
}

// validateYAML is kept as the local-profile validator; local profiles must be
// real Clash configs too.
func validateYAML(b []byte) error { return ValidateConfig(b) }

func validateProfileContent(typ config.ProfileType, b []byte) error {
	switch typ {
	case config.ProfileScript:
		if len(strings.TrimSpace(string(b))) == 0 {
			return fmt.Errorf("empty script")
		}
		return nil
	case config.ProfileComposition:
		_, err := decodeYAMLMap(b)
		return err
	case config.ProfileMerge, config.ProfileRules, config.ProfileProxies, config.ProfileGroups:
		_, err := decodeYAMLMap(b)
		return err
	default:
		return ValidateConfig(b)
	}
}

func decodeYAMLMap(b []byte) (map[string]any, error) {
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("expected a non-empty YAML mapping")
	}
	return m, nil
}

// decodeSubscription handles plain YAML and base64-encoded subscriptions.
func decodeSubscription(b []byte) []byte {
	trimmed := strings.TrimSpace(string(b))
	if strings.Contains(trimmed, "proxies:") || strings.Contains(trimmed, "proxy-groups:") || strings.HasPrefix(trimmed, "#") {
		return b
	}
	// Try standard and raw-url base64.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if dec, err := enc.DecodeString(strings.TrimSpace(trimmed)); err == nil {
			return dec
		}
	}
	return b
}

// decodeSubscriptionFromFile is the spill counterpart of decodeSubscription.
// The raw response already lives in a file, so we never materialize it as one
// big slice: we peek only the leading bytes to tell plain YAML apart from
// base64, then use base64.NewDecoder (a streaming decoder) for the encoded
// case. Plain YAML still needs a full read because validateYAML parses the
// whole document, but it is read straight from disk rather than from the
// network buffer.
func decodeSubscriptionFromFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Peek enough of the header to spot plain-YAML markers (they always appear
	// near the top of a Clash config), then rewind for the real read.
	peek := make([]byte, 4096)
	n, _ := io.ReadFull(f, peek)
	peek = peek[:n]
	trimmed := strings.TrimSpace(string(peek))
	if strings.Contains(trimmed, "proxies:") || strings.Contains(trimmed, "proxy-groups:") || strings.HasPrefix(trimmed, "#") {
		return os.ReadFile(path)
	}

	// Stream-decode base64, trying the same encodings as the in-memory path.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		var out bytes.Buffer
		if _, err := io.Copy(&out, base64.NewDecoder(enc, f)); err == nil {
			return out.Bytes(), nil
		}
	}
	// Not base64 after all: fall back to the raw bytes, matching decodeSubscription.
	return os.ReadFile(path)
}

func parseTrafficHeaders(h http.Header) *config.ProfileTraffic {
	parse := func(key string) int64 {
		v := h.Get(key)
		var n int64
		_, _ = fmt.Sscanf(v, "%d", &n)
		return n
	}
	return &config.ProfileTraffic{
		Upload: parse("upload"), Download: parse("download"),
		Total: parse("total"), Expire: parse("expire"),
	}
}

// DefaultProfile is a minimal starter config so the app works on first run.
const DefaultProfile = `port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
