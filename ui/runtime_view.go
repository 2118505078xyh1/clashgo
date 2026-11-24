package ui

import (
	"encoding/json"

	"github.com/egoist/mygo/ui"
)

// showRuntimeConfig fetches the effective config from 自研内核 and shows it
// in a read-only dialog (lightweight version of a config inspector).
func (a *App) showRuntimeConfig() {
	go func() {
		cfg, err := a.currentClient().Configs()
		if err != nil {
			a.win.Update(func() { a.notify("错误", "读取运行时配置失败: "+err.Error()) })
			return
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		a.win.Update(func() {
			a.RuntimeConfigText = string(b)
			a.RuntimeConfigOpen = true
		})
	}()
}

func (a *App) overlayRuntimeConfig(c *ui.Context) {
	ui.Modal(c, &a.RuntimeConfigOpen, func() {
		ui.Column(c).Width(760).Height(620).Padding(20).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "运行时配置").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					a.RuntimeConfigOpen = false
				}
			})
			text(c, "以下是当前生效的配置（只读）").FontSize(11).TextColor(c.Theme().TextMuted)
			ui.TextArea(c, &a.RuntimeConfigText).Grow(1)
		})
	})
}
