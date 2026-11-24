//go:build windows

package ssid

import (
	"clashgo/internal/hidewin"
	"regexp"
	"strings"
)

var ssidRe = regexp.MustCompile(`(?i)SSID\s*:\s*(.+)`)

// Current returns the currently connected Wi-Fi SSID on Windows.
func Current() (string, error) {
	out, err := hidewin.Command("netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return "", err
	}
	m := ssidRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return "", nil
	}
	return strings.TrimSpace(m[1]), nil
}
