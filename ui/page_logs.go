package ui

import (
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

func (a *App) pageLogs(c *ui.Context) {
	// Filter by level and search text.
	var filtered []struct {
		line  string
		color ui.Color
	}
	for _, l := range a.Logs {
		lt := strings.ToLower(l.Type)
		switch a.LogLevelFilter {
		case "info":
			if lt != "info" && lt != "debug" {
				continue
			}
		case "warning":
			if lt != "warning" {
				continue
			}
		case "error":
			if lt != "error" {
				continue
			}
		}
		if a.Search != "" && !containsFold(l.Payload, a.Search) {
			continue
		}
		color := c.Theme().Text
		switch lt {
		case "error":
			color = c.Theme().Danger
		case "warning":
			color = c.Theme().Warning
		case "info":
			color = c.Theme().Success
		}
		filtered = append(filtered, struct {
			line  string
			color ui.Color
		}{l.Time + "  " + l.Payload, color})
	}

	// 正序/倒序（对齐 Clash Verge 的排序切换）
	if a.LogNewestFirst {
		for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
			filtered[i], filtered[j] = filtered[j], filtered[i]
		}
	}

	ui.Column(c).Fill().Padding(20).Gap(12).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			text(c, a.tr("logs")).FontSize(22).Bold().Grow(1)
			// 暂停/继续（对齐 Clash Verge）
			pauseLabel := "暂停"
			if a.LogPaused {
				pauseLabel = "继续"
			}
			if ui.Button(c, pauseLabel).Clicked() {
				a.LogPaused = !a.LogPaused
			}
			// 正序/倒序
			sortLabel := "正序"
			if a.LogNewestFirst {
				sortLabel = "倒序"
			}
			if ui.Button(c, sortLabel).Clicked() {
				a.LogNewestFirst = !a.LogNewestFirst
			}
			levelSel := a.levelFilterLabel()
			ui.Combobox(c, &levelSel, []string{"全部", "信息", "警告", "错误"}).Width(90).OnChange(func() {
				switch levelSel {
				case "信息":
					a.LogLevelFilter = "info"
				case "警告":
					a.LogLevelFilter = "warning"
				case "错误":
					a.LogLevelFilter = "error"
				default:
					a.LogLevelFilter = ""
				}
			})
			ui.TextInput(c, &a.Search).Placeholder("搜索日志…").Width(160)
			ui.Checkbox(c, &a.LogFollow, "自动滚动")
			if ui.Button(c, a.trs("清空")).Clicked() {
				a.Logs = nil
			}
			if ui.Button(c, "复制").Clicked() {
				var b strings.Builder
				for _, l := range filtered {
					b.WriteString(l.line)
					b.WriteByte('\n')
				}
				mygo.Clipboard.WriteText(b.String())
			}
			if ui.Button(c, "导出").Clicked() {
				a.exportLogs()
			}
		})

		logState := ui.ListState{FollowEnd: a.LogFollow}
		ui.List(c, &logState, len(filtered), func(i int) {
			text(c, filtered[i].line).FontSize(12).TextColor(filtered[i].color).Padding(4, 8).Selectable()
		}).Grow(1).Background(c.Theme().Surface).Radius(8)
	})
}

func (a *App) levelFilterLabel() string {
	switch a.LogLevelFilter {
	case "info":
		return "信息"
	case "warning":
		return "警告"
	case "error":
		return "错误"
	default:
		return "全部"
	}
}
