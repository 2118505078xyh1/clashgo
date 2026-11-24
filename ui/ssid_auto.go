package ui

import (
	"strings"
	"time"

	"clashgo/internal/ssid"
)

// startSSIDAutomation periodically checks the connected Wi-Fi SSID and
// toggles the system proxy based on the allowlist (idea from common practice).
func (a *App) startSSIDAutomation() {
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		lastSSID := ""
		for range ticker.C {
			if !a.Settings.EnableSSIDRule {
				continue
			}
			current, err := ssid.Current()
			if err != nil || current == "" || current == lastSSID {
				continue
			}
			lastSSID = current
			allowed := ssidAllowed(current, a.Settings.SSIDAllowlist)
			a.win.Update(func() {
				if allowed != a.Settings.EnableSystemProxy {
					a.Settings.EnableSystemProxy = allowed
					a.applySystemProxy()
					a.Notices.Push("ssid::change", "网络 "+current+" → 代理"+
						map[bool]string{true: "开", false: "关"}[allowed], 0)
				}
			})
		}
	}()
}

func ssidAllowed(current, allowlist string) bool {
	if strings.TrimSpace(allowlist) == "" {
		return true // no list = always on
	}
	for _, s := range strings.Split(allowlist, ",") {
		if strings.TrimSpace(s) == current {
			return true
		}
	}
	return false
}
