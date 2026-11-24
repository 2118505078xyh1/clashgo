//go:build windows

package installer

import (
	"fmt"
	"os/exec"
	"syscall"
)

// AddAutoStart adds clashgo to the current user's Run key.
func AddAutoStart(exePath string) error {
	// Use single-quoted PowerShell string with doubled single quotes.
	v := "'" + stringsReplaceAll(exePath, "'", "''") + "'"
	ps := fmt.Sprintf(`New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ClashGo" -Value %s -Force | Out-Null`, v)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// RemoveAutoStart removes the Run key entry.
func RemoveAutoStart() error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ClashGo" -ErrorAction SilentlyContinue`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func stringsReplaceAll(s, old, new string) string {
	out := ""
	for i := 0; i < len(s); i++ {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			out += new
			i += len(old) - 1
		} else {
			out += string(s[i])
		}
	}
	return out
}
