// Package updater checks for new releases via the GitHub API.
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// defaultAPI is a placeholder; real deployments should override it with
// their own release endpoint via Checker.APIURL.
const defaultAPI = "https://api.github.com/repos/clashgo/clashgo/releases/latest"

// Release describes the fields we need from a GitHub release.
type Release struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
	PublishedAt string `json:"published_at"`
}

// Checker queries a GitHub releases endpoint.
type Checker struct {
	APIURL string
	Client *http.Client
}

// New creates a checker with the default self-hosted release endpoint.
func New() *Checker {
	return &Checker{APIURL: defaultAPI, Client: &http.Client{Timeout: 15 * time.Second}}
}

// Latest fetches the latest release.
func (c *Checker) Latest(ctx context.Context) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.APIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "clashgo")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// Compare returns >0 if a > b, <0 if a < b, 0 if equal. Handles "v1.2.3" and "1.2.3-beta".
func Compare(a, b string) int {
	parse := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		if i := strings.IndexAny(s, "-+"); i >= 0 {
			s = s[:i]
		}
		parts := strings.Split(s, ".")
		out := make([]int, 3)
		for i := 0; i < 3 && i < len(parts); i++ {
			out[i], _ = strconv.Atoi(parts[i])
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] > pb[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

// AssetForPlatform picks the release asset matching GOOS/GOARCH.
func (r *Release) AssetForPlatform(goos, goarch string) string {
	name := ""
	switch goos {
	case "windows":
		if goarch == "386" {
			name = "x86"
		} else {
			name = "x64"
		}
	case "darwin":
		if goarch == "arm64" {
			name = "aarch64-apple-darwin"
		} else {
			name = "x86_64-apple-darwin"
		}
	case "linux":
		if goarch == "arm64" {
			name = "aarch64"
		} else {
			name = "x86_64"
		}
	}
	for _, a := range r.Assets {
		lower := strings.ToLower(a.Name)
		if strings.Contains(lower, strings.ToLower(name)) &&
			(strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dmg") ||
				strings.HasSuffix(lower, ".msi") || strings.HasSuffix(lower, ".app.tar.gz") ||
				strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".deb")) {
			return a.BrowserDownloadURL
		}
	}
	return r.HTMLURL
}
