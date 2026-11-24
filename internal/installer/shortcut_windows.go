// Package installer creates Windows shortcuts (.lnk) via PowerShell COM.
package installer

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// psQuote returns a PowerShell single-quoted string literal. Go's %q doubles
// backslashes, which leaves Windows paths with doubled separators in the
// shortcut's working directory/icon and in registry values. Backslashes are
// literal inside PowerShell single quotes; only a single quote needs doubling.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// CreateShortcut creates a Windows .lnk shortcut at linkPath pointing to
// target, with optional arguments, working dir, description and icon.
func CreateShortcut(linkPath, target, args, workDir, desc, iconPath string) error {
	// Build a PowerShell script that uses WScript.Shell to create the .lnk.
	ps := fmt.Sprintf(`
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut(%s)
$sc.TargetPath = %s
$sc.Arguments = %s
$sc.WorkingDirectory = %s
$sc.Description = %s
`, psQuote(linkPath), psQuote(target), psQuote(args), psQuote(workDir), psQuote(desc))
	if iconPath != "" {
		ps += fmt.Sprintf("$sc.IconLocation = %s\n", psQuote(iconPath))
	}
	ps += "$sc.Save()\n"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	// Hide the console window.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create shortcut: %w (%s)", err, string(out))
	}
	return nil
}

// DesktopPath returns the current user's Desktop directory.
func DesktopPath() (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"[Environment]::GetFolderPath('Desktop')")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	path := ""
	for _, c := range string(out) {
		if c != '\r' && c != '\n' {
			path += string(c)
		}
	}
	return path, nil
}

// StartMenuPath returns the user's Start Menu Programs directory.
func StartMenuPath() (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"[Environment]::GetFolderPath('Programs')")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	path := ""
	for _, c := range string(out) {
		if c != '\r' && c != '\n' {
			path += string(c)
		}
	}
	return path, nil
}

// AddUninstallEntry registers the app in "Add/Remove Programs" (per-user,
// no elevation needed).
func AddUninstallEntry(displayName, installDir, exePath, version string) error {
	ps := fmt.Sprintf(`
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ClashGo"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name "DisplayName" -Value %s | Out-Null
New-ItemProperty -Path $key -Name "DisplayVersion" -Value %s | Out-Null
New-ItemProperty -Path $key -Name "InstallLocation" -Value %s | Out-Null
New-ItemProperty -Path $key -Name "DisplayIcon" -Value %s | Out-Null
New-ItemProperty -Path $key -Name "UninstallString" -Value ('"' + %s + '" --uninstall') | Out-Null
New-ItemProperty -Path $key -Name "Publisher" -Value "ClashGo" | Out-Null
`, psQuote(displayName), psQuote(version), psQuote(installDir), psQuote(exePath), psQuote(exePath))
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add uninstall entry: %w (%s)", err, string(out))
	}
	return nil
}

// RemoveUninstallEntry removes the registry entry.
func RemoveUninstallEntry() error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ClashGo" -Recurse -Force -ErrorAction SilentlyContinue`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// InstalledLocation reads InstallLocation from the uninstall registry entry.
func InstalledLocation() string {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ClashGo' -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	loc := strings.TrimSpace(string(out))
	// Installs made by older builds stored the path with doubled backslashes
	// (Go's %q inside the PowerShell script). Normalise those so RemoveAll
	// and shortcut cleanup act on the real directory.
	loc = strings.ReplaceAll(loc, `\\`, `\`)
	return loc
}

// ShortcutPath joins a directory and a .lnk name.
func ShortcutPath(dir, name string) string {
	return filepath.Join(dir, name+".lnk")
}
