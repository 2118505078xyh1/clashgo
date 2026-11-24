package sysproxy

import (
	"clashgo/internal/winreg"
	"fmt"
)

func setAutoOS(enable bool, pacURL string) error {
	key, err := winreg.OpenKey(winreg.CURRENT_USER, internetSettings, winreg.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if enable {
		if err := key.SetStringValue("AutoConfigURL", pacURL); err != nil {
			return err
		}
		// PAC mode should not have manual proxy enabled.
		_ = key.SetDWordValue("ProxyEnable", 0)
	} else {
		_ = key.DeleteValue("AutoConfigURL")
	}
	if err := refreshWinINET(); err != nil {
		return fmt.Errorf("refresh after PAC: %w", err)
	}
	return nil
}

func getAutoOS() (*AutoProxy, error) {
	key, err := winreg.OpenKey(winreg.CURRENT_USER, internetSettings, winreg.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	u, _, err := key.GetStringValue("AutoConfigURL")
	if err != nil {
		return &AutoProxy{}, nil
	}
	return &AutoProxy{Enable: u != "", URL: u}, nil
}
