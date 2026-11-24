//go:build !windows

package autostart

import (
	"os"
	"path/filepath"
)

const desktopEntry = `[Desktop Entry]
Type=Application
Name=ClashGo
Exec=%s
Terminal=false
`

func Enable(appName string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	p := filepath.Join(dir, ".config", "autostart", "clashgo.desktop")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(formatEntry(desktopEntry, exe)), 0o644)
}

func Disable(appName string) error {
	dir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(dir, ".config", "autostart", "clashgo.desktop"))
}

func Enabled(appName string) bool {
	dir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, ".config", "autostart", "clashgo.desktop"))
	return err == nil
}

func OpenSettings() error { return nil }

func formatEntry(tmpl, exe string) string {
	out := tmpl
	for i := 0; i < len(out); i++ {
		_ = i
	}
	return replaceOnce(tmpl, "%s", exe)
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}
