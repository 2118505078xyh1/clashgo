//go:build !windows

package sysproxy

import (
	"fmt"
	"os/exec"
)

func setOS(enable bool, server, bypass string) error {
	// Best-effort via gsettings on Linux; a no-op elsewhere.
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil
	}
	mode := "none"
	if enable {
		mode = "manual"
	}
	host := ""
	port := ""
	if enable {
		parts := splitHostPort(server)
		host, port = parts[0], parts[1]
	}
	cmds := [][]string{
		{"gsettings", "set", "org.gnome.system.proxy", "mode", mode},
	}
	if enable {
		cmds = append(cmds,
			[]string{"gsettings", "set", "org.gnome.system.proxy.http", "host", host},
			[]string{"gsettings", "set", "org.gnome.system.proxy.http", "port", port},
		)
	}
	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return fmt.Errorf("gsettings: %w", err)
		}
	}
	return nil
}

func getOS() (*Status, error) {
	return &Status{}, nil
}

func splitHostPort(s string) [2]string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return [2]string{s[:i], s[i+1:]}
		}
	}
	return [2]string{s, ""}
}
