package profile

import (
	"strings"

	"clashgo/internal/config"
)

// ImportBatch imports multiple subscription URLs, skipping duplicates and
// reporting per-item results. Returns (imported count, errors).
func (m *Manager) ImportBatch(namePrefix, text string, opts *config.PrfOption) (int, []string) {
	var urls []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		u := strings.TrimSpace(line)
		if u == "" || !strings.HasPrefix(u, "http") {
			continue
		}
		if seen[u] {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
	}
	// Also skip URLs already imported.
	existing := map[string]bool{}
	for _, item := range m.DB.Items {
		if item.URL != "" {
			existing[item.URL] = true
		}
	}
	imported := 0
	var errs []string
	for i, u := range urls {
		if existing[u] {
			errs = append(errs, "跳过重复: "+u)
			continue
		}
		name := namePrefix
		if len(urls) > 1 {
			name = namePrefix + " " + itoa(i+1)
		}
		if _, err := m.ImportRemote(name, u, opts); err != nil {
			errs = append(errs, u+": "+err.Error())
		} else {
			imported++
		}
	}
	return imported, errs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
