package ui

import (
	"log"

	"github.com/egoist/mygo"

	"clashgo/internal/sysproxy"
)

// RegisterHotkeys registers global shortcuts if enabled in settings.
func (a *App) RegisterHotkeys(win *mygo.Window) {
	if !a.Settings.EnableHotkeys {
		return
	}
	if a.Settings.HotkeyToggle != "" {
		err := mygo.GlobalShortcut.Register(a.Settings.HotkeyToggle, func() {
			a.Settings.EnableSystemProxy = !a.Settings.EnableSystemProxy
			server := "127.0.0.1:" + itoa(a.Settings.MixedPort)
			if err := sysproxy.Set(a.Settings.EnableSystemProxy, server, a.Settings.ProxyBypass); err != nil {
				log.Printf("hotkey sysproxy: %v", err)
			}
			a.mustSaveSettings()
			a.win.Invalidate()
		})
		if err != nil {
			log.Printf("register toggle hotkey: %v", err)
		}
	}
	if a.Settings.HotkeyShow != "" {
		err := mygo.GlobalShortcut.Register(a.Settings.HotkeyShow, func() {
			win.Show()
			win.Focus()
		})
		if err != nil {
			log.Printf("register show hotkey: %v", err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
