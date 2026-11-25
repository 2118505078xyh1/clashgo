package ui

import (
	"github.com/egoist/mygo/ui"
)

// proxyStatusCard 是首页最重要的一块：整卡可点开关系统代理。
//
// 视觉上有两种状态：
//   - 关闭：中性表面 + 虚线感边框 + 灰色图标，明确"待启用"。
//   - 开启：品牌渐变填充 + 发光图标 + 实时速率，一眼看出"正在工作"。
func (a *App) proxyStatusCard(c *ui.Context) {
	on := a.Settings.EnableSystemProxy

	card := ui.Row(c).FillWidth().FillHeight().MinHeight(104).Padding(spaceLg).Gap(spaceMd).
		Radius(radiusLg).AlignItems(ui.Center).Cursor(ui.CursorPointer)
	if on {
		card.LinearGradient(brandGradient()).
			Shadow(0, 10, 28, -6, withAlpha(ui.Hex(brandSecondary), 0.55))
	} else {
		card.Background(ui.Hex(surfaceCard)).
			Border(1, ui.Hex(borderStrong))
	}

	card.Children(func() {
		// 状态图标：开启时用发光圆底，关闭时用中性底。
		iconBox := ui.Box(c).Size(46, 46).Radius(radiusMd).Center()
		if on {
			iconBox.Background(withAlpha(ui.Hex("#FFFFFF"), 0.18)).
				Shadow(0, 4, 14, -2, withAlpha(ui.Hex("#FFFFFF"), 0.35))
		} else {
			iconBox.Background(ui.Hex(surfaceHover))
		}
		iconBox.Children(func() {
			icon := iconBlock
			fg := ui.Hex(textTertiary)
			if on {
				icon = iconCheck
				fg = ui.Hex("#FFFFFF")
			}
			ui.Icon(c, icon).FontSize(24).TextColor(fg)
		})

		ui.Column(c).Gap(3).Grow(1).Children(func() {
			if on {
				text(c, "代理已开启").FontSize(18).Bold().TextColor(ui.Hex("#FFFFFF"))
				ui.Row(c).Gap(8).Children(func() {
					text(c, humanBytes(a.Down+a.Up)+" 已转发").FontSize(11).TextColor(withAlpha(ui.Hex("#FFFFFF"), 0.85))
					badge(c, modeLabel(a.Settings.Mode), ui.Hex("#FFFFFF"), withAlpha(ui.Hex("#000000"), 0.18))
				})
			} else {
				text(c, "代理未开启").FontSize(18).Bold()
				text(c, "点击开启系统代理").FontSize(11).TextColor(ui.Hex(textTertiary))
			}
		})

		// 右侧：开启时显示实时速率，关闭时显示引导箭头。
		if on {
			ui.Column(c).Gap(1).AlignItems(ui.End).Children(func() {
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					text(c, "↓").FontSize(11).TextColor(withAlpha(ui.Hex("#FFFFFF"), 0.8))
					text(c, humanRate(a.DownRate)).FontSize(12).Bold().TextColor(ui.Hex("#FFFFFF"))
				})
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					text(c, "↑").FontSize(11).TextColor(withAlpha(ui.Hex("#FFFFFF"), 0.8))
					text(c, humanRate(a.UpRate)).FontSize(12).Bold().TextColor(ui.Hex("#FFFFFF"))
				})
			})
		} else {
			ui.Box(c).Size(30, 30).Radius(radiusFull).Center().
				Background(ui.Hex(surfaceHover)).
				Children(func() {
					ui.Icon(c, iconChevronRight).FontSize(16).TextColor(ui.Hex(textTertiary))
				})
		}
	})
	if card.Clicked() {
		a.Settings.EnableSystemProxy = !on
		a.applySystemProxy()
	}
}
