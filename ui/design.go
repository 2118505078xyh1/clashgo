package ui

import (
	"github.com/egoist/mygo/ui"
)

// 本文件是重设计后的基础组件库。
//
// 设计原则：
//  1. 层次靠表面明度差（surfaceBase → raised → card → overlay）建立，
//     而不是靠边框堆砌。默认无边框，只有需要强调时才出现。
//  2. 强调色只用在真正需要用户注意的地方（主按钮、选中态、品牌标识）。
//  3. 圆角与间距来自统一令牌，避免"每个页面自己拍脑袋"。

// text 是所有标签的统一入口。
func text(c *ui.Context, s string) ui.Element { return ui.Text(c, s) }

// card 是一张标准卡片：抬起的表面 + 柔和投影 + 统一内边距。
//
// 内边距与行间距刻意保持紧凑：桌面客户端的信息密度比网页高，
// 卡片过肥会让人一眼看不到真正重要的内容。
func card(c *ui.Context, fn func()) ui.Element {
	t := c.Theme()
	return ui.Column(c).Padding(spaceMd).Gap(spaceSm).
		Background(t.Surface).
		Radius(radiusMd).
		Shadow(0, 4, 14, -4, elevationShadow(1)).
		Children(fn)
}

// cardFlat 是不带投影的卡片，用于内容密集、需要紧凑感的区域。
func cardFlat(c *ui.Context, fn func()) ui.Element {
	t := c.Theme()
	return ui.Column(c).Padding(spaceMd).Gap(spaceSm).
		Background(t.Surface).
		Radius(radiusMd).
		Children(fn)
}

// cardAccent 是带强调色左边框的卡片，用于突出最重要的信息。
func cardAccent(c *ui.Context, accent ui.Color, fn func()) ui.Element {
	t := c.Theme()
	return ui.Column(c).Padding(spaceMd).Gap(spaceSm).
		Background(t.Surface).
		Border(1, withAlpha(accent, 0.35)).
		Radius(radiusMd).
		Shadow(0, 4, 14, -4, elevationShadow(1)).
		Children(fn)
}

// rowCard 是行式卡片：内容水平排列、高度固定，用于列表型内容。
// 这样每条只占一行，不用一张卡包一整块。
func rowCard(c *ui.Context, fn func()) ui.Element {
	t := c.Theme()
	return ui.Row(c).AlignItems(ui.Center).Gap(spaceMd).Padding(spaceSm, spaceMd).
		Background(t.Surface).
		Radius(radiusSm).
		Children(fn)
}

// sectionTitle 是带副标题的小节标题。
func sectionTitle(c *ui.Context, title, subtitle string) {
	ui.Row(c).Gap(spaceSm).AlignItems(ui.Baseline).Children(func() {
		text(c, title).FontSize(14).Bold()
		if subtitle != "" {
			text(c, subtitle).FontSize(11).TextColor(ui.Hex(textTertiary))
		}
	})
}

// iconBadge 是一个圆角方块图标容器：给图标一个统一的底色与留白。
func iconBadge(c *ui.Context, icon *ui.SVG, fg, bg ui.Color, size int) ui.Element {
	return ui.Box(c).Size(float32(size), float32(size)).Center().Radius(radiusSm).
		Background(bg).
		Children(func() {
			ui.Icon(c, icon).FontSize(float32(size) * 0.55).TextColor(fg)
		})
}

// badge 是一个小标签（状态、分类）。
func badge(c *ui.Context, label string, fg, bg ui.Color) ui.Element {
	return ui.Box(c).Padding(2, 7).Radius(radiusFull).
		Background(bg).
		Children(func() {
			text(c, label).FontSize(10).Bold().TextColor(fg)
		})
}

// pillButton 是一个胶囊形状的次级按钮。
func pillButton(c *ui.Context, label, tooltip string, onClick func()) ui.Element {
	t := c.Theme()
	e := ui.Box(c).Padding(4, 11).Radius(radiusFull).
		Background(t.Surface).
		Border(1, t.Border).
		Children(func() {
			text(c, label).FontSize(11).Bold().TextColor(t.Text)
		})
	e.Cursor(ui.CursorPointer)
	if tooltip != "" {
		e.Tooltip(tooltip)
	}
	if e.Hovered() {
		e.Background(t.SurfaceHover)
	}
	if e.Clicked() {
		onClick()
	}
	return e
}

// primaryButton 是主操作按钮：品牌渐变填充，白字。
func primaryButton(c *ui.Context, label string, onClick func()) ui.Element {
	t := c.Theme()
	e := ui.Box(c).Padding(6, 14).Radius(radiusSm).
		LinearGradient(accentGradient(t.Accent)).
		Shadow(0, 3, 10, -2, withAlpha(t.Accent, 0.45)).
		Children(func() {
			text(c, label).FontSize(12).Bold().TextColor(t.AccentText)
		})
	e.Cursor(ui.CursorPointer)
	if e.Hovered() {
		e.LinearGradient(accentGradient(t.AccentHover))
	}
	if e.Clicked() {
		onClick()
	}
	return e
}

// ghostButton 是次级按钮：透明底 + 细边框。
func ghostButton(c *ui.Context, label string, onClick func()) ui.Element {
	t := c.Theme()
	e := ui.Box(c).Padding(6, 14).Radius(radiusSm).
		Border(1, t.Border).
		Children(func() {
			text(c, label).FontSize(12).Bold().TextColor(t.Text)
		})
	e.Cursor(ui.CursorPointer)
	if e.Hovered() {
		e.Background(t.SurfaceHover)
	}
	if e.Clicked() {
		onClick()
	}
	return e
}

// statTile 是一个指标块：大号数字 + 标签 + 左侧色条。
func statTile(c *ui.Context, label, value, hint string, accent ui.Color) ui.Element {
	t := c.Theme()
	return ui.Row(c).Gap(spaceMd).AlignItems(ui.Center).Padding(spaceMd).
		Background(t.Surface).Radius(radiusMd).
		Children(func() {
			ui.Box(c).Width(3).Height(34).Radius(radiusFull).Background(accent)
			ui.Column(c).Gap(2).Grow(1).Children(func() {
				text(c, value).FontSize(19).Bold()
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					text(c, label).FontSize(12).TextColor(t.TextMuted)
					if hint != "" {
						text(c, hint).FontSize(11).TextColor(accent)
					}
				})
			})
		})
}

// divider 是细分隔线。
func divider(c *ui.Context) {
	ui.Box(c).Height(1).FillWidth().Background(c.Theme().Border)
}
