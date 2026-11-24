//go:build !windows

package sysproxy

import "os/exec"

func setAutoOS(enable bool, pacURL string) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return nil
	}
	mode := "none"
	if enable {
		mode = "auto"
	}
	if err := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", mode).Run(); err != nil {
		return err
	}
	if enable {
		return exec.Command("gsettings", "set", "org.gnome.system.proxy", "autostart-url", pacURL).Run()
	}
	return nil
}

func getAutoOS() (*AutoProxy, error) { return &AutoProxy{}, nil }
