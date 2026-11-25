package ui

import (
	"fmt"
	"sort"

	"github.com/egoist/mygo/ui"
)

// text is kept as a thin wrapper so every label goes through one place.
// （实现在 design.go —— 新组件库）

// pageHeader is the shared page heading: an 18px title, at most one or two
// actions on the right, and the always-available help button.
func (a *App) minimizeToTray() {
	if a.win == nil {
		return
	}
	a.SetHidden(true)
	a.win.Hide()
}

// pageHeader 是页面顶部的操作栏。
//
// 不再显示页面标题：侧栏已经高亮了当前页面，标题是重复信息。
// 这里只放该页特有的操作按钮。
func (a *App) pageHeader(c *ui.Context, extra func()) {
	if extra == nil {
		return
	}
	ui.Row(c).AlignItems(ui.Center).Gap(spaceSm).Children(func() {
		ui.Spacer(c).Grow(1)
		extra()
	})
}

// navTile is one cell of the sidebar's 2-column icon grid: a 24px icon at
// top-left, a short status at top-right and a bold title at the bottom.
// The whole tile fills with the primary color when active.
// navRow 是 Clash Verge 风格的侧边栏导航项：图标 + 文字整行可点，
// 选中项高亮。对应 Verge 的 LayoutItem。
func navRow(c *ui.Context, icon *ui.SVG, label string, active bool, onClick func()) {
	t := c.Theme()
	// 选中态：强调色底 + 左侧竖条 + 强调色文字；未选中时靠悬停给反馈。
	row := ui.Row(c).Gap(11).AlignItems(ui.Center).Padding(10, 12).Radius(radiusMd)
	if active {
		row.Background(withAlpha(t.Accent, 0.16))
	} else if row.Hovered() {
		row.Background(ui.Hex(surfaceHover))
	}
	row.Children(func() {
		// 左侧指示条：选中时才占位，避免文字跳动。
		bar := ui.Box(c).Width(3).Height(18).Radius(radiusFull)
		if active {
			bar.Background(t.Accent)
		} else {
			bar.Background(ui.Hex("#00000000"))
		}
		ico := ui.Hex(textTertiary)
		labelColor := ui.Hex(textSecondary)
		if active {
			ico, labelColor = t.Accent, t.Text
		}
		ui.Box(c).Size(20, 20).Center().Children(func() {
			ui.Icon(c, icon).FontSize(19).TextColor(ico)
		})
		text(c, label).FontSize(13).Bold().TextColor(labelColor).Grow(1)
	})
	row.Cursor(ui.CursorPointer)
	if row.Clicked() {
		onClick()
	}
}

func navTile(c *ui.Context, icon *ui.SVG, label, status string, active bool, onClick func()) {
	t := c.Theme()
	e := ui.Column(c).Grow(1).MinWidth(0).Gap(8).Padding(12, 10).MinHeight(78).Radius(12)
	iconColor, textColor, statusColor := t.Accent, t.Text, t.TextMuted
	if active {
		e.Background(t.Accent)
		iconColor, textColor, statusColor = t.AccentText, t.AccentText, withAlpha(t.AccentText, 0.8)
	} else {
		e.Background(t.Surface).Border(1, t.Border)
	}
	e.Children(func() {
		ui.Row(c).AlignItems(ui.Start).Children(func() {
			ui.Box(c).Size(24, 24).Center().Children(func() {
				ui.Icon(c, icon).FontSize(24).TextColor(iconColor)
			}).Grow(1)
			if status != "" {
				text(c, status).FontSize(10).TextColor(statusColor)
			}
		})
		text(c, label).FontSize(13).Bold().TextColor(textColor)
	})
	if e.Hovered() && !active {
		e.Background(withAlpha(t.Accent, 0.30))
	}
	e.Cursor(ui.CursorPointer)
	e.ContextMenu(func(m *ui.Menu) {
		if m.Item("复制").Chosen() {
			c.WriteClipboard(label)
		}
	})
	if e.Clicked() {
		onClick()
	}
}

// miniSwitchCard 是 Clash Party 风格的两列开关卡片。
func miniSwitchCard(c *ui.Context, icon *ui.SVG, label string, value *bool, onChange func()) {
	t := c.Theme()
	e := ui.Column(c).Grow(1).MinWidth(0).Gap(12).Padding(12, 10).MinHeight(82).
		Radius(12).Background(t.Surface).Border(1, t.Border)
	e.Children(func() {
		ui.Row(c).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(24, 24).Center().Children(func() {
				ui.Icon(c, icon).FontSize(24).TextColor(t.Text)
			}).Grow(1)
			if ui.Switch(c, value).Changed() {
				onChange()
			}
		})
		text(c, label).FontSize(13).Bold()
	})
}

// switchTile is a full-width sidebar card with an always-visible toggle.
func switchTile(c *ui.Context, icon *ui.SVG, label string, value *bool, onChange func()) {
	t := c.Theme()
	ui.Row(c).Gap(9).AlignItems(ui.Center).Padding(10, 11).
		Background(t.Surface).Border(1, t.Border).Radius(partyRadiusMedium).
		Children(func() {
			ui.Box(c).Size(24, 24).Center().Children(func() {
				ui.Icon(c, icon).FontSize(20).TextColor(t.Accent)
			})
			text(c, label).FontSize(13).Bold().Grow(1)
			if ui.Switch(c, value).Changed() {
				onChange()
			}
		})
}

// sidebarModes 代理模式：默认显示当前模式一句话，点击展开带说明的选项。
// 直连模式对普通用户与"关闭系统代理"等价，故 UI 只保留规则/全局。
func (a *App) sidebarModes(c *ui.Context) {
	t := c.Theme()
	cur := a.Settings.Mode
	label := "规则（推荐）"
	if cur == "global" {
		label = "全局 · 全部走代理"
	}
	ui.Column(c).Gap(6).Padding(10, 11).
		Background(t.Surface).Border(1, t.Border).Radius(partyRadiusMedium).
		Children(func() {
			text(c, "代理模式").FontSize(11).Bold().TextColor(t.TextMuted)
			if ui.Button(c, "● "+label).Clicked() {
				a.ModeMenuOpen = !a.ModeMenuOpen
			}
			if a.ModeMenuOpen {
				for _, m := range []struct{ key, label, desc string }{
					{"rule", "规则 ✓推荐", "国内直连，国外走代理（日常用这个）"},
					{"global", "全局", "全部走代理，费流量、国内变慢"},
				} {
					mk := m.key
					sel := cur == mk
					b := ui.Row(c).Gap(6).AlignItems(ui.Center).Padding(6, 8).Radius(8)
					if sel {
						b.Background(withAlpha(t.Accent, 0.18))
					} else {
						b.Background(t.SurfaceHover)
					}
					b.Children(func() {
						text(c, m.label).FontSize(11).Bold().Grow(1).TextColor(t.Text)
					})
					if b.Clicked() {
						a.setMode(mk)
						a.ModeMenuOpen = false
					}
					text(c, m.desc).FontSize(9).TextColor(t.TextMuted).Padding(0, 8, 4, 8)
				}
				text(c, "想不代理？直接关闭左侧的「系统代理」即可").FontSize(9).TextColor(t.TextMuted).Padding(2, 8, 0, 8)
			}
		})
}

// iconAction 是一个方形小图标按钮，用于卡片右上角的次要操作（测速/定位等）。
func iconAction(c *ui.Context, icon *ui.SVG, tooltip string, onClick func(), disabled bool) {
	t := c.Theme()
	b := ui.Button(c, "").Width(28).Height(28).Padding(0).Radius(8).Center().
		Disabled(disabled).Tooltip(tooltip)
	b.Children(func() {
		ui.Icon(c, icon).FontSize(16).TextColor(t.TextMuted)
	})
	if b.Clicked() {
		onClick()
	}
}

// toolButton is an entry on the settings page that opens one of the
// secondary pages (rules, logs, unlock, DNS, requests) through the router.
func toolButton(c *ui.Context, icon *ui.SVG, label, colHex string, onClick func()) {
	t := c.Theme()
	col := ui.Hex(colHex)
	b := ui.Row(c).Gap(9).AlignItems(ui.Center).Padding(9, 11).
		Radius(partyRadiusMedium).Background(t.Surface).Border(1, t.Border).Cursor(ui.CursorPointer)
	b.Children(func() {
		ui.Box(c).Size(26, 26).Radius(partyRadiusSmall).Background(withAlpha(col, 0.16)).Center().
			Children(func() { ui.Icon(c, icon).FontSize(15).TextColor(col) })
		text(c, label).FontSize(12).Bold()
	})
	if b.Hovered() {
		b.Background(withAlpha(col, 0.24)).Border(1, withAlpha(col, 0.5))
	}
	b.ContextMenu(func(m *ui.Menu) {
		if m.Item("复制").Chosen() {
			c.WriteClipboard(label)
		}
	})
	if b.Clicked() {
		onClick()
	}
}

// statusColor picks a semantic color for a boolean state.
func statusColor(c *ui.Context, ok bool) ui.Color {
	if ok {
		return c.Theme().Success
	}
	return c.Theme().TextMuted
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanRate(n int64) string { return humanBytes(n) + "/s" }

func delayText(ms int) string {
	if ms < 0 {
		return "超时"
	}
	if ms == 0 {
		return "-"
	}
	return fmt.Sprintf("%d ms", ms)
}

func sortStrings(s []string) { sort.Strings(s) }

func (a *App) setMode(mode string) {
	a.Settings.Mode = mode
	a.mustSaveSettings()
	go func() {
		if err := a.currentClient().SetMode(mode); err != nil {
			logf("set mode: %v", err)
		}
	}()
}

// modeLabel 返回代理模式的中文显示。
func modeLabel(mode string) string {
	switch mode {
	case "rule":
		return "规则模式"
	case "global":
		return "全局模式"
	case "direct":
		return "直连模式"
	}
	return mode
}
