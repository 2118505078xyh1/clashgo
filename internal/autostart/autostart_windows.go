// Package autostart manages starting clashgo at user login.
package autostart

import (
	"clashgo/internal/hidewin"
	"clashgo/internal/winreg"
	"fmt"
	"os"
	"strconv"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// Enable adds clashgo to the user's Run key.
func Enable(appName string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	key, err := winreg.OpenKey(winreg.CURRENT_USER, runKey, winreg.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	// Quote path so spaces are handled; just the exe is enough — the app
	// restores its previous window state itself.
	return key.SetStringValue(appName, strconv.Quote(exe))
}

// Disable removes the Run key entry.
func Disable(appName string) error {
	key, err := winreg.OpenKey(winreg.CURRENT_USER, runKey, winreg.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.DeleteValue(appName)
}

// Enabled reports whether the Run key entry exists.
func Enabled(appName string) bool {
	key, err := winreg.OpenKey(winreg.CURRENT_USER, runKey, winreg.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	v, _, err := key.GetStringValue(appName)
	return err == nil && v != ""
}

// OpenSettings opens the OS startup-apps settings page.
func OpenSettings() error {
	return hidewin.Command("cmd", "/C", "start", "ms-settings:startupapps").Run()
}

var _ = fmt.Sprintf
