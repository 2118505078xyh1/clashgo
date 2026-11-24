package installer

import (
	"os"
	"path/filepath"
	"strings"
)

// DefaultInstallDir returns the default per-user installation directory.
// It is shared by the installer wizard and by the --uninstall entry point so
// both agree on what "a default install" means.
func DefaultInstallDir() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, AppName)
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	return filepath.Join(home, "AppData", "Local", AppName)
}

// Uninstall removes ClashGo: the autostart entry, the installed files (the
// location recorded in the registry plus the default location, so stale
// registry entries from earlier builds are cleaned too) and the shortcuts.
// Every step is best-effort: an already-missing file or registry key is not
// an error, which makes uninstall safe to run more than once.
func Uninstall() {
	_ = RemoveAutoStart()

	dir := InstalledLocation()
	def := DefaultInstallDir()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	if !samePath(def, dir) {
		_ = os.RemoveAll(def)
	}

	if desk, err := DesktopPath(); err == nil && desk != "" {
		_ = os.Remove(ShortcutPath(desk, AppName))
	}
	if sm, err := StartMenuPath(); err == nil && sm != "" {
		_ = os.RemoveAll(filepath.Join(sm, AppName))
	}

	_ = RemoveUninstallEntry()
}

// samePath compares two install locations without letting case or trailing
// separators defeat the "already removed" check.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}
