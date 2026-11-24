package ui

import "github.com/egoist/mygo/ui"

// safeOpen keeps the safety overlay's visibility independent of the App
// struct: ShowSafe can be called from anywhere (e.g. a tray action) without
// requiring an extra field on App.
var safeOpen bool

// ShowSafe opens the safe-mode / read-only overlay on the next frame.
func (a *App) ShowSafe() {
	safeOpen = true
}

// overlaySafe renders the safety settings dialog. The main view calls it from
// its overlay block; both checkboxes bind directly to the persisted settings.
func (a *App) overlaySafe(c *ui.Context) {
	ui.Modal(c, &safeOpen, func() {
		ui.Column(c).Width(480).Padding(24).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "安全选项").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					safeOpen = false
				}
			})

			ui.Checkbox(c, &a.Settings.SafeMode, "Safe mode（安全模式）")
			text(c, "启动时移除 listeners/tunnels、清空 external-controller 并关闭 allow-lan，避免内核把代理端口或控制接口暴露到局域网。").
				FontSize(11).TextColor(c.Theme().TextMuted)

			ui.Checkbox(c, &a.Settings.ReadOnly, "Read-only（只读模式）")
			text(c, "只读模式下所有写操作（修改配置、设置、代理选择等）都会被拒绝，仅保留查看能力。").
				FontSize(11).TextColor(c.Theme().TextMuted)

			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "保存并关闭").Clicked() {
					a.mustSaveSettings()
					safeOpen = false
				}
			})
		})
	})
}
