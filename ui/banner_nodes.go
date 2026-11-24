package ui

import (
	"github.com/egoist/mygo/ui"
)

// allNodesDownBanner 在首页提示“所有节点当前都不可用”。
//
// 安全约定：这里只做提示，绝不自动关闭系统代理。
// 系统代理的开关必须由用户自己点击，否则会在用户不知情时改变整机网络走向。
func (a *App) allNodesDownBanner(c *ui.Context) {
	if !a.NodesAllDown {
		return
	}
	t := c.Theme()
	warn := themeColor("warning")
	b := ui.Column(c).FillWidth().Gap(10).Padding(16).Radius(14).
		Background(withAlpha(warn, 0.12)).Border(1, withAlpha(warn, 0.35))
	b.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, iconInfo).FontSize(18).TextColor(warn)
			text(c, "所有节点当前都不可用").FontSize(15).Bold().Grow(1)
		})
		text(c, "代理流量会全部失败。如果当前网络已经不通，可以手动关闭系统代理恢复直连。").FontSize(12).TextColor(t.Text)
		ui.Row(c).Gap(10).Children(func() {
			if ui.Button(c, "重新检测").Clicked() {
				go func() {
					ok := a.checkNodesHealth()
					a.win.Update(func() {})
					if !ok {
						a.notify("节点检测", "所有节点都不可用")
					}
				}()
			}
			if ui.Button(c, "关闭系统代理").Clicked() {
				a.Settings.EnableSystemProxy = false
				a.applySystemProxy()
				a.notify("系统代理", "已关闭系统代理，当前网络走直连")
			}
		})
	})
}
