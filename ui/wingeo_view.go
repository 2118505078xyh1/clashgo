package ui

import (
	"fmt"

	"github.com/egoist/mygo/ui"
)

// wingeoOpen is intentionally package-level: main.go can call ShowWindowGeo
// from a tray menu or hotkey without having to touch the App struct.
var wingeoOpen bool

// ShowWindowGeo opens the window-geometry settings dialog. The main program
// is responsible for calling overlayWindowGeo from its overlay dispatcher
// and for wiring WindowOptions load/save.
func (a *App) ShowWindowGeo() {
	wingeoOpen = true
}

const (
	defaultWindowWidth  = 1000
	defaultWindowHeight = 700
	defaultWindowX      = 80
	defaultWindowY      = 60
)

func (a *App) overlayWindowGeo(c *ui.Context) {
	ui.Modal(c, &wingeoOpen, func() {
		ui.Column(c).Width(420).Padding(24).Gap(12).Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "窗口几何").FontSize(18).Bold().Grow(1)
				if ui.Button(c, a.tr("close")).Clicked() {
					wingeoOpen = false
				}
			})
			if a.win == nil {
				// Headless render (screenshots/tests): the real window is
				// managed and saved by main.go.
				text(c, "由主程序自动保存").FontSize(12).TextColor(c.Theme().TextMuted)
			} else {
				b := a.win.Bounds()
				text(c, "位置："+fmt.Sprintf("%d, %d", b.X, b.Y)).FontSize(12)
				text(c, "尺寸："+fmt.Sprintf("%d × %d", b.Width, b.Height)).FontSize(12)
				text(c, "最大化："+fmt.Sprintf("%t", a.win.IsMaximized())).FontSize(12)
			}
			text(c, "关闭窗口时由主程序自动保存位置与尺寸。").
				FontSize(11).TextColor(c.Theme().TextMuted)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "重置为默认").Clicked() {
					if a.win != nil {
						a.win.Unmaximize()
						a.win.SetSize(defaultWindowWidth, defaultWindowHeight)
						a.win.SetPosition(defaultWindowX, defaultWindowY)
					}
					wingeoOpen = false
				}
			})
		})
	})
}
