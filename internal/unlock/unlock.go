// Package unlock implements media unlock detection through the local proxy.
package unlock

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Item describes one detection entry and its result.
type Item struct {
	Name      string `json:"name" yaml:"name"`
	Status    string `json:"status" yaml:"status"`
	Region    string `json:"region" yaml:"region"`
	CheckTime string `json:"check_time" yaml:"check_time"`
}

// Checker runs media unlock checks through a local mixed proxy.
type Checker struct {
	ProxyURL string
	Timeout  time.Duration
	client   *http.Client
	mu       sync.Mutex
}

// New creates a checker using the given mixed-port (e.g. 7897).
func New(mixedPort int) *Checker {
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", mixedPort)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	return &Checker{
		ProxyURL: proxyURL,
		Timeout:  15 * time.Second,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
	}
}

// Names returns all default check item names in order.
func Names() []string {
	return []string{
		"哔哩哔哩大陆", "哔哩哔哩港澳台", "ChatGPT Web", "Claude", "Gemini",
		"Muse AI", "YouTube Premium", "Bahamut Anime", "Netflix", "Disney+",
		"Prime Video", "Spotify", "TikTok",
	}
}

// PendingItems returns the initial list of all-pending items.
func PendingItems() []Item {
	out := make([]Item, 0, len(Names()))
	for _, name := range Names() {
		out = append(out, Item{Name: name, Status: "Pending"})
	}
	return out
}

const defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
const bahamutUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

// Check runs one named check.
func (c *Checker) Check(ctx context.Context, name string) Item {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	item := Item{Name: name, Status: "Failed"}
	var status, region string
	var err error
	switch name {
	case "哔哩哔哩大陆":
		status, err = checkBilibili(ctx, c, "82846771", "307247")
	case "哔哩哔哩港澳台":
		status, err = checkBilibili(ctx, c, "18281381", "183799")
	case "ChatGPT Web":
		status, region, err = checkChatGPT(ctx, c)
	case "Claude":
		status, region, err = checkClaude(ctx, c)
	case "Gemini":
		status, region, err = checkGemini(ctx, c)
	case "Muse AI":
		status, err = checkMuse(ctx, c)
	case "YouTube Premium":
		status, region, err = checkYouTube(ctx, c)
	case "Bahamut Anime":
		status, region, err = checkBahamut(ctx, c)
	case "Netflix":
		status, region, err = checkNetflix(ctx, c)
	case "Disney+":
		status, region, err = checkDisney(ctx, c)
	case "Prime Video":
		status, region, err = checkPrimeVideo(ctx, c)
	case "Spotify":
		status, region, err = checkSpotify(ctx, c)
	case "TikTok":
		status, region, err = checkTikTok(ctx, c)
	default:
		err = fmt.Errorf("unknown check: %s", name)
	}
	if err != nil {
		item.Status = "Failed (" + err.Error() + ")"
	} else {
		item.Status = status
	}
	item.Region = region
	item.CheckTime = time.Now().Format("2006-01-02 15:04:05")
	return item
}

// CheckAll runs all checks with a concurrency limit of 4, streaming results.
func (c *Checker) CheckAll(ctx context.Context, onComplete func(Item)) []Item {
	names := Names()
	results := make([]Item, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			item := c.Check(ctx, name)
			results[i] = item
			if onComplete != nil {
				onComplete(item)
			}
		}(i, name)
	}
	wg.Wait()
	return results
}

// request performs an HTTP GET through the proxy and returns status and body.
func (c *Checker) request(ctx context.Context, urlStr, ua string, headers map[string]string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return 0, "", "", err
	}
	if ua == "" {
		ua = defaultUA
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Request.URL.String(), "", err
	}
	return resp.StatusCode, resp.Request.URL.String(), string(body), nil
}

func statusFromHTTP(code int) (string, bool) {
	if code == 403 || code == 451 {
		return "No", true
	}
	if code < 200 || code >= 300 {
		return "Failed", true
	}
	return "", false
}

func contains(s, sub string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(sub)) }

func extractQuotedField(body, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(body, needle)
	if i < 0 {
		return ""
	}
	rest := body[i+len(needle):]
	j := strings.Index(rest, ":")
	if j < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[j+1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	k := strings.Index(rest, `"`)
	if k < 0 {
		return ""
	}
	return rest[:k]
}
