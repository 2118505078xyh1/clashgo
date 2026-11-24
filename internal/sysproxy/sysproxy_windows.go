package sysproxy

import (
	"clashgo/internal/hidewin"
	"clashgo/internal/winreg"
	"strings"
	"syscall"
	"unsafe"
)

const (
	internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	// WinINet option flags.
	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

// setOS applies the proxy to every Windows connection (LAN plus RAS/VPN
// dial-up entries). The LAN-only part lives in setLANOnly so SetAllConnections
// can reuse it without recursing.
func setOS(enable bool, server, bypass string) error {
	return SetAllConnections(enable, server, bypass)
}

// setLANOnly updates the classic "Internet Options -> LAN settings" registry
// values and notifies WinINet. It is the LAN half of SetAllConnections.
func setLANOnly(enable bool, server, bypass string) error {
	key, err := winreg.OpenKey(winreg.CURRENT_USER, internetSettings, winreg.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if err := key.SetDWordValue("ProxyEnable", boolToInt(enable)); err != nil {
		return err
	}
	if enable {
		if err := key.SetStringValue("ProxyServer", server); err != nil {
			return err
		}
		if bypass != "" {
			if err := key.SetStringValue("ProxyOverride", bypass); err != nil {
				return err
			}
		}
	}
	return refreshWinINET()
}

func getOS() (*Status, error) {
	key, err := winreg.OpenKey(winreg.CURRENT_USER, internetSettings, winreg.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	enabledVal, _, _ := key.GetIntegerValue("ProxyEnable")
	server, _, _ := key.GetStringValue("ProxyServer")
	bypass, _, _ := key.GetStringValue("ProxyOverride")
	return &Status{Enable: uint32(enabledVal) != 0, Server: server, Bypass: bypass}, nil
}

// refreshWinINET notifies running applications of the proxy change by calling
// wininet!InternetSetOptionW directly — no PowerShell process, no cmd window.
func refreshWinINET() error {
	if err := wininet.Load(); err != nil {
		return fallbackRefresh()
	}
	ret, _, callErr := internetSetOption.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	if ret == 0 {
		_ = callErr
	}
	internetSetOption.Call(0, INTERNET_OPTION_REFRESH, 0, 0)
	return nil
}

// fallbackRefresh is used only if wininet cannot be loaded.
func fallbackRefresh() error {
	cmd := hidewin.Command("rundll32", "user32.dll,UpdatePerUserSystemParameters")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	_ = strings.TrimSpace(string(out))
	return nil
}

func boolToInt(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

var _ = unsafe.Pointer(nil)
