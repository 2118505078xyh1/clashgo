// Package resources manages 自研内核's rule resource files (GeoIP, GeoSite,
// MetaDB, ASN) inside the application home directory.
package resources

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ResourceInfo describes one downloadable 自研内核 resource file.
type ResourceInfo struct {
	Name      string
	File      string
	URL       string
	Installed bool
	Size      int64
	ModTime   time.Time
}

// DefaultResources is the catalog of known resources. URLs point at the
// official release assets, proxied through ghproxy.net so downloads work in
// networks where GitHub cannot be reached directly.
var DefaultResources = []ResourceInfo{
	{
		Name: "GeoIP",
		File: "GeoIP.dat",
		URL:  "https://ghproxy.net/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
	},
	{
		Name: "GeoSite",
		File: "GeoSite.dat",
		URL:  "https://ghproxy.net/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
	},
	{
		Name: "GeoIP MetaDB",
		File: "geoip.metadb",
		URL:  "https://ghproxy.net/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
	},
	{
		Name: "ASN",
		File: "ASN.mmdb",
		URL:  "https://ghproxy.net/https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/ASN.mmdb",
	},
}

var httpClient = &http.Client{Timeout: 10 * time.Minute}

// List scans dir and reports the installation state of each known resource.
func List(dir string) []ResourceInfo {
	out := make([]ResourceInfo, 0, len(DefaultResources))
	for _, r := range DefaultResources {
		info := r
		if st, err := os.Stat(filepath.Join(dir, r.File)); err == nil && !st.IsDir() {
			info.Installed = true
			info.Size = st.Size()
			info.ModTime = st.ModTime()
		}
		out = append(out, info)
	}
	return out
}

// Download fetches url into a temporary file in dir and then atomically
// renames it over the target named name. An existing file is only replaced
// after the whole download has succeeded.
func Download(dir, name, url string) error {
	name = safeName(name)
	if name == "" {
		return fmt.Errorf("resource name is required")
	}
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("resource url is required: %s", name)
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download %s: HTTP %s", name, resp.Status)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if st, err := os.Stat(tmpName); err == nil && st.Size() == 0 {
		return fmt.Errorf("download %s: empty file", name)
	}
	return replaceFile(tmpName, filepath.Join(dir, name))
}

// Delete removes an installed resource. A missing file is not an error.
func Delete(dir, name string) error {
	name = safeName(name)
	if name == "" {
		return fmt.Errorf("resource name is required")
	}
	err := os.Remove(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// replaceFile moves src over dst. On Windows os.Rename refuses to replace an
// existing file, so the old file is removed first in that case.
func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(src, dst)
}

// safeName keeps a caller-supplied name inside dir.
func safeName(name string) string {
	name = filepath.Base(filepath.FromSlash(name))
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return ""
	}
	return name
}
