package ui

import (
	"fmt"
	"sort"

	"github.com/egoist/mygo/ui"
)

// text is kept as a thin wrapper so every label goes through one place.
func text(c *ui.Context, s string) ui.Element { return ui.Text(c, s) }

// Three levels of elevation used by cards, popovers and dialogs.
func shadowLevel(level int) ui.Color {
	switch level {
	case 1:
		return withAlpha(ui.Hex("#000000"), 0.22)
	case 3:
		return withAlpha(ui.Hex("#000000"), 0.45)
	default:
		return withAlpha(ui.Hex("#000000"), 0.32)
	}
}

// card builds an elevated panel with consistent padding and rounded corners.
func card(c *ui.Context, fn func()) ui.Element {
	t := c.Theme()
	return ui.Column(c).Padding(18).Gap(12).
		Background(t.Surface).
		Border(1, t.Border).
		Radius(partyRadiusLarge).
		Shadow(0, 4, 16, -2, shadowLevel(2)).
		Children(fn)
}

// sectionTitle builds a bold title with a subtle subtitle.
func sectionTitle(c *ui.Context, title, subtitle string) {
	ui.Row(c).Gap(10).AlignItems(ui.Baseline).Children(func() {
		text(c, title).FontSize(16).Bold()
		if subtitle != "" {
			text(c, subtitle).FontSize(12).TextColor(c.Theme().TextMuted)
		}
	})
}

// pageHeader is the shared page heading: an 18px title, at most one or two
// actions on the right, and the always-available help button.
func (a *App) minimizeToTray() {
	if a.win == nil {
		return
	}
	a.SetHidden(true)
	a.win.Hide()
}

func (a *App) pageHeader(c *ui.Context, title string, extra func()) {
	ui.Row(c).AlignItems(ui.Center).Gap(8).Padding(0, 0, 4, 0).Children(func() {
		text(c, title).FontSize(18).Bold().Grow(1)
		if extra != nil {
			extra()
		}
		if ui.Button(c, "最小化到托盘").Tooltip("隐藏窗口；双击托盘图标可恢复").Clicked() {
			a.minimizeToTray()
		}
		if ui.Button(c, "?").Tooltip("使用说明").Width(30).Clicked() {
			a.HelpOpen = true
		}
	})
}

// helpOverlay is the "使用说明" dialog opened from any page header.
func (a *App) helpOverlay(c *ui.Context) {
	ui.Modal(c, &a.HelpOpen, func() {
		card(c, func() {
			text(c, "使用说明").FontSize(18).Bold()
			ui.Divider(c).Padding(2, 0)
			for _, line := range []string{
				"【3 步上手】",
				"1. 导入订阅：进入「配置」页 →「导入订阅」→ 粘贴订阅地址，导入后自动激活。",
				"2. 选择节点：进入「代理」页 → 点击代理组展开 → 在节点上点「选择」。（也可直接用自动选择）",
				"3. 开启代理：点首页顶部大卡片，或左侧栏「系统代理」开关。开启后即可科学上网。",
				"",
				"【代理模式】规则（推荐）：国内直连、国外走代理；全局：全部走代理，费流量、国内变慢，仅排错时临时用。想不代理就关「系统代理」。",
				"【TUN 模式】虚拟网卡，接管所有程序的流量（含不支持系统代理的软件），需管理员权限；普通用户不用开。",
				"【托盘】点右上角「最小化到托盘」可隐藏窗口；双击托盘图标恢复，右键可开关代理、显示窗口、退出。右上角 X 会关闭程序。",
				"【更多】规则/日志/媒体解锁/DNS/请求记录在「设置 → 工具与诊断」。",
			} {
				text(c, line).FontSize(12).TextColor(c.Theme().Text)
			}
			if ui.PrimaryButton(c, "知道了").Clicked() {
				a.HelpOpen = false
			}
		}).Width(500).Selectable()
	})
}

// navTile is one cell of the sidebar's 2-column icon grid: a 24px icon at
// top-left, a short status at top-right and a bold title at the bottom.
// The whole tile fills with the primary color when active.
// navRow 是 Clash Verge 风格的侧边栏导航项：图标 + 文字整行可点，
// 选中项高亮。对应 Verge 的 LayoutItem。
func navRow(c *ui.Context, icon *ui.SVG, label string, active bool, onClick func()) {
	t := c.Theme()
	e := ui.Row(c).Gap(14).AlignItems(ui.Center).Padding(11, 14).Radius(10)
	if active {
		e.Background(withAlpha(t.Accent, 0.18))
	} else if e.Hovered() {
		e.Background(withAlpha(t.Accent, 0.08))
	}
	e.Children(func() {
		ico := t.TextMuted
		labelColor := t.Text
		if active {
			ico, labelColor = t.Accent, t.Accent
		}
		ui.Box(c).Size(22, 22).Center().Children(func() {
			ui.Icon(c, icon).FontSize(20).TextColor(ico)
		})
		text(c, label).FontSize(14).Bold().TextColor(labelColor).Grow(1)
	})
	e.Cursor(ui.CursorPointer)
	if e.Clicked() {
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
