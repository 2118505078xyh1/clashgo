package ui

import (
	"github.com/egoist/mygo/ui"
)

// proxyStatusCard 参考移动端设计的大状态卡：整卡可点开关系统代理，
// 未开启时显示"点此开启代理"，开启后显示"已转发 X"。
func (a *App) proxyStatusCard(c *ui.Context) {
	t := c.Theme()
	on := a.Settings.EnableSystemProxy

	// 卡片背景：开启用主色，未开启用次级表面色。
	card := ui.Row(c).FillWidth().Height(88).Padding(18).Gap(16).
		Radius(14).AlignItems(ui.Center).Cursor(ui.CursorPointer)
	if on {
		card.Background(t.Accent)
	} else {
		card.Background(t.Surface).Border(1, t.Border)
	}

	card.Children(func() {
		// 状态图标
		icon := iconBlock
		if on {
			icon = iconCheck
		}
		ui.Box(c).Size(44, 44).Radius(12).Center().
			Background(withAlpha(t.Background, 0.16)).
			Children(func() {
				ui.Icon(c, icon).FontSize(24).TextColor(t.Background)
			})
		ui.Column(c).Gap(4).Children(func() {
			if on {
				text(c, "代理中").FontSize(17).Bold().TextColor(t.Background)
				text(c, humanBytes(a.Down+a.Up)+" 已转发").FontSize(12).TextColor(withAlpha(t.Background, 0.85))
			} else {
				text(c, "未代理").FontSize(17).Bold().TextColor(t.Text)
				text(c, "点此开启代理").FontSize(12).TextColor(t.TextMuted)
			}
		}).Grow(1)
		// 右侧状态小字
		if on {
			text(c, modeLabel(a.Settings.Mode)).FontSize(12).TextColor(withAlpha(t.Background, 0.85))
		}
	})
	if card.Clicked() {
		a.Settings.EnableSystemProxy = !on
		a.applySystemProxy()
	}
}
