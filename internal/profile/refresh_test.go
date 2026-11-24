package profile

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clashgo/internal/config"
	"clashgo/internal/paths"
)

const testClashYAML = `port: 7890
proxies:
  - name: node-1
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-groups:
  - name: PROXY
    type: select
    proxies: [node-1]
rules:
  - MATCH,PROXY
`

func withProfileDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldProfiles, oldDB := paths.Profiles, paths.ProfilesDB
	paths.Profiles, paths.ProfilesDB = dir, filepath.Join(dir, "profiles.yaml")
	t.Cleanup(func() { paths.Profiles, paths.ProfilesDB = oldProfiles, oldDB })
}

func TestValidateConfigRejectsErrorPages(t *testing.T) {
	cases := map[string]string{
		"cloudflare html": `<!DOCTYPE html><html><body><h1>Sorry, you have been blocked</h1></body></html>`,
		"json error":      `{"message":"token is error"}`,
		"empty":           "",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateConfig([]byte(body)); err == nil {
				t.Fatalf("ValidateConfig accepted %s", name)
			}
		})
	}
	if err := ValidateConfig([]byte(testClashYAML)); err != nil {
		t.Fatalf("ValidateConfig rejected a valid config: %v", err)
	}
}

func TestRefreshKeepsLastGoodProfileOnBadResponse(t *testing.T) {
	withProfileDir(t)
	m := &Manager{DB: &config.ProfilesDB{}}
	item := &config.PrfItem{
		UID: "remote-1", Type: config.ProfileRemote, Name: "sub",
		File: "remote-1.yaml", Updated: 1,
	}
	if err := os.WriteFile(filepath.Join(paths.Profiles, item.File), []byte(testClashYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	m.DB.Items = append(m.DB.Items, item)
	m.DB.Current = item.UID

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>Sorry, you have been blocked</body></html>`))
	}))
	defer srv.Close()
	item.URL = srv.URL

	if err := m.Refresh(item.UID); err == nil {
		t.Fatal("Refresh accepted an HTML error page")
	}
	got, err := os.ReadFile(filepath.Join(paths.Profiles, item.File))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testClashYAML {
		t.Fatalf("Refresh overwrote the good profile:\n%s", got)
	}
}

func TestRefreshUsesProfileOptions(t *testing.T) {
	withProfileDir(t)
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		if r.URL.Query().Get("url") != "https://example.com/sub" {
			t.Errorf("convert target did not wrap the source URL: %s", r.URL.RawQuery)
		}
		w.Header().Set("upload", "12")
		w.Header().Set("download", "34")
		_, _ = w.Write([]byte(testClashYAML))
	}))
	defer srv.Close()

	m := &Manager{DB: &config.ProfilesDB{}}
	item := &config.PrfItem{
		UID: "remote-2", Type: config.ProfileRemote, Name: "sub",
		File: "remote-2.yaml", URL: "https://example.com/sub",
		Option: &config.PrfOption{
			UserAgent:      "Mozilla/5.0 (clashgo-test/1.0)",
			ConvertTarget:  srv.URL + "/sub?target=clash",
			TimeoutSeconds: 3,
		},
	}
	if err := os.WriteFile(filepath.Join(paths.Profiles, item.File), []byte("port: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.DB.Items = append(m.DB.Items, item)
	m.DB.Current = item.UID

	if err := m.Refresh(item.UID); err != nil {
		t.Fatal(err)
	}
	if gotUA != "Mozilla/5.0 (clashgo-test/1.0)" {
		t.Fatalf("unexpected User-Agent %q", gotUA)
	}
	got, err := os.ReadFile(filepath.Join(paths.Profiles, item.File))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testClashYAML {
		t.Fatalf("profile was not refreshed: %q", got)
	}
	if item.Extra == nil || item.Extra.Upload != 12 || item.Extra.Download != 34 {
		t.Fatalf("traffic headers not recorded: %+v", item.Extra)
	}
}

func TestSaveContentKeepsScriptAttachment(t *testing.T) {
	withProfileDir(t)
	m := &Manager{DB: &config.ProfilesDB{}}
	item := &config.PrfItem{UID: "s123", Type: config.ProfileScript, File: "s123.js"}
	if err := os.WriteFile(filepath.Join(paths.Profiles, item.File), []byte("// old"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "function main(config) { return config; }\n"
	if err := m.SaveContent(item, []byte(script)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(paths.Profiles, item.File))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(script) {
		t.Fatalf("script content changed: %q", got)
	}
}

// 旧界面写入的 clashgo/1.0 不能覆盖浏览器 UA，否则订阅服务会返回 403。
func TestRefreshIgnoresLegacyDefaultUserAgent(t *testing.T) {
	withProfileDir(t)
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(testClashYAML))
	}))
	defer srv.Close()

	m := &Manager{DB: &config.ProfilesDB{}}
	item := &config.PrfItem{
		UID: "remote-legacy", Type: config.ProfileRemote, Name: "sub",
		File: "remote-legacy.yaml", URL: srv.URL,
		Option: &config.PrfOption{UserAgent: "clashgo/1.0", TimeoutSeconds: 3},
	}
	if err := os.WriteFile(filepath.Join(paths.Profiles, item.File), []byte("port: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.DB.Items = append(m.DB.Items, item)
	m.DB.Current = item.UID
	if err := m.Refresh(item.UID); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotUA, "Mozilla/") {
		t.Fatalf("legacy UA was not replaced with a browser UA: %q", gotUA)
	}
}

func TestDeleteProfileSwitchToNextAndThenEmpty(t *testing.T) {
	withProfileDir(t)
	m := &Manager{DB: &config.ProfilesDB{}}
	first := &config.PrfItem{UID: "a", Type: config.ProfileLocal, Name: "a", File: "a.yaml"}
	second := &config.PrfItem{UID: "b", Type: config.ProfileLocal, Name: "b", File: "b.yaml"}
	for _, item := range []*config.PrfItem{first, second} {
		if err := os.WriteFile(filepath.Join(paths.Profiles, item.File), []byte(testClashYAML), 0o644); err != nil {
			t.Fatal(err)
		}
		m.DB.Items = append(m.DB.Items, item)
	}
	m.DB.Current = first.UID

	if err := m.Delete(first.UID); err != nil {
		t.Fatal(err)
	}
	if len(m.DB.Items) != 1 || m.DB.Current != second.UID {
		t.Fatalf("delete did not switch to the remaining profile: items=%d current=%q", len(m.DB.Items), m.DB.Current)
	}
	if _, err := os.Stat(filepath.Join(paths.Profiles, first.File)); !os.IsNotExist(err) {
		t.Fatalf("deleted profile file still exists: %v", err)
	}

	if err := m.Delete(second.UID); err != nil {
		t.Fatal(err)
	}
	if len(m.DB.Items) != 0 || m.DB.Current != "" {
		t.Fatalf("last profile was not removed cleanly: items=%d current=%q", len(m.DB.Items), m.DB.Current)
	}
}
