package ui

import (
	"github.com/egoist/mygo/ui"
)

// modeCard 是首页的代理模式选择行。
//
// 三档模式用分段控件（segmented control）呈现：整个分段是一个底槽，
// 选中项用强调色填充并带轻微上浮的阴影，比三个独立按钮更有"一组"的感觉。
// 不加标题——这一行本身就是模式选择，不需要额外说明。
func (a *App) modeCard(c *ui.Context) {
	t := c.Theme()
	card(c, func() {
		ui.Box(c).Padding(4).Radius(radiusMd).Background(ui.Hex(surfaceBase)).Children(func() {
			ui.Row(c).Gap(4).Children(func() {
				for _, m := range []struct{ key, label, hint string }{
					{"rule", "规则", "国内直连"},
					{"global", "全局", "全部代理"},
					{"direct", "直连", "全部直连"},
				} {
					mk, ml, mh := m.key, m.label, m.hint
					sel := a.Settings.Mode == mk
					seg := ui.Column(c).Grow(1).Gap(1).Padding(7, 4).Radius(radiusSm).Center()
					if sel {
						seg.LinearGradient(accentGradient(t.Accent)).
							Shadow(0, 3, 10, -2, withAlpha(t.Accent, 0.5))
					}
					fg, sub := t.Text, ui.Hex(textTertiary)
					if sel {
						fg, sub = t.AccentText, withAlpha(t.AccentText, 0.75)
					}
					seg.Children(func() {
						text(c, ml).FontSize(13).Bold().TextColor(fg)
						text(c, mh).FontSize(10).TextColor(sub)
					})
					seg.Cursor(ui.CursorPointer)
					if !sel && seg.Hovered() {
						seg.Background(ui.Hex(surfaceHover))
					}
					if seg.Clicked() {
						a.setMode(mk)
					}
				}
			})
		})
	})
}

// networkCard 是首页的虚拟网卡开关。
//
// 做成「整块可点、开启后变色」的样式，而不是一个系统 Switch 控件：
// 与上方大状态卡的交互一致（都是整块点击），也更好看。
//
// 只放虚拟网卡：系统代理已经由上方的大状态卡整卡控制，
// 这里再放一个同名开关属于重复。
func (a *App) networkCard(c *ui.Context) {
	t := c.Theme()
	on := a.Settings.EnableTUN

	box := ui.Row(c).FillWidth().FillHeight().Padding(spaceMd).Gap(spaceMd).AlignItems(ui.Center).
		Radius(radiusMd).Cursor(ui.CursorPointer)
	if on {
		box.LinearGradient(accentGradient(t.Accent)).
			Shadow(0, 6, 18, -4, withAlpha(t.Accent, 0.5))
	} else {
		box.Background(ui.Hex(surfaceHover))
	}
	box.Children(func() {
		// 状态点：开时是亮色实心，关时是灰的。
		dot := ui.Hex(textTertiary)
		if on {
			dot = ui.Hex("#FFFFFF")
		}
		ui.Box(c).Size(10, 10).Radius(5).Background(dot)

		ui.Column(c).Gap(2).Grow(1).Children(func() {
			title := "虚拟网卡 (TUN)"
			sub := "接管所有程序流量"
			tc, sc := t.Text, ui.Hex(textTertiary)
			if on {
				tc, sc = ui.Hex("#FFFFFF"), withAlpha(ui.Hex("#FFFFFF"), 0.8)
			}
			text(c, title).FontSize(13).Bold().TextColor(tc)
			text(c, sub).FontSize(10).TextColor(sc)
		})

		// 右侧文字开关：开时显示"已开启"，关时显示"已关闭"。
		state := "已关闭"
		stateColor := ui.Hex(textTertiary)
		if on {
			state = "已开启"
			stateColor = ui.Hex("#FFFFFF")
		}
		text(c, state).FontSize(11).Bold().TextColor(stateColor)
	})
	if box.Clicked() {
		a.Settings.EnableTUN = !on
		a.mustSaveSettings()
		a.reapplyCore()
	}
}
