package profile

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clashgo/internal/config"
	"clashgo/internal/paths"
)

// largeYAML builds a plain Clash config large enough to cross spillThreshold.
func largeYAML(nodes int) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "  - name: node-%d\n    type: socks5\n    server: 127.0.0.1\n    port: %d\n", i, 1080+i%1000)
	}
	b.WriteString("proxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [node-0]\n")
	b.WriteString("rules:\n  - MATCH,PROXY\n")
	return b.String()
}

// TestImportRemoteSpillLargeResponse verifies that a >2 MiB subscription is
// spilled to a temp file, decoded correctly and stored as a valid profile.
func TestImportRemoteSpillLargeResponse(t *testing.T) {
	dir := t.TempDir()
	oldProfiles, oldDB := paths.Profiles, paths.ProfilesDB
	paths.Profiles, paths.ProfilesDB = dir, filepath.Join(dir, "profiles.yaml")
	defer func() { paths.Profiles, paths.ProfilesDB = oldProfiles, oldDB }()

	body := largeYAML(60000) // ~4.5 MiB
	if len(body) <= spillThreshold {
		t.Fatalf("test body too small: %d bytes", len(body))
	}

	t.Run("plain yaml", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()

		m := &Manager{DB: &config.ProfilesDB{}}
		item, err := m.ImportRemoteSpill("big", srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if item.Type != config.ProfileRemote || item.Name != "big" || item.URL != srv.URL {
			t.Fatalf("unexpected item: %+v", item)
		}
		content, err := m.Content(item)
		if err != nil {
			t.Fatal(err)
		}
		if len(content) <= spillThreshold {
			t.Fatalf("stored profile too small: %d bytes", len(content))
		}
		if string(content) != body {
			t.Fatalf("stored profile differs from subscription body")
		}
		if _, err := os.Stat(filepath.Join(paths.Profiles, item.File)); err != nil {
			t.Fatalf("profile file missing: %v", err)
		}
	})

	t.Run("base64 subscription", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(body))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(encoded))
		}))
		defer srv.Close()

		m := &Manager{DB: &config.ProfilesDB{}}
		item, err := m.ImportRemoteSpill("big-b64", srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		content, err := m.Content(item)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != body {
			t.Fatalf("base64 spill decoded incorrectly (got %d bytes, want %d)", len(content), len(body))
		}
	})
}

// TestImportRemoteSmallResponse confirms the public ImportRemote entry point
// still works for responses below the spill threshold (delegation path).
func TestImportRemoteSmallResponse(t *testing.T) {
	dir := t.TempDir()
	oldProfiles, oldDB := paths.Profiles, paths.ProfilesDB
	paths.Profiles, paths.ProfilesDB = dir, filepath.Join(dir, "profiles.yaml")
	defer func() { paths.Profiles, paths.ProfilesDB = oldProfiles, oldDB }()

	body := "proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	m := &Manager{DB: &config.ProfilesDB{}}
	item, err := m.ImportRemote("small", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	content, err := m.Content(item)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != body {
		t.Fatalf("small profile mismatch: %q", content)
	}
}
