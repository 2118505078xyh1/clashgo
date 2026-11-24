//go:build !windows

package installer

import "fmt"

func CreateShortcut(linkPath, target, args, workDir, desc, iconPath string) error {
	return fmt.Errorf("shortcuts only supported on Windows")
}
func DesktopPath() (string, error)   { return "", fmt.Errorf("Windows only") }
func StartMenuPath() (string, error) { return "", fmt.Errorf("Windows only") }
func AddUninstallEntry(displayName, installDir, exePath, version string) error {
	return fmt.Errorf("Windows only")
}
func RemoveUninstallEntry() error          { return fmt.Errorf("Windows only") }
func InstalledLocation() string            { return "" }
func ShortcutPath(dir, name string) string { return dir + "/" + name + ".lnk" }
