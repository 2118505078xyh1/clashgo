package ui

import (
	"context"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/unlock"
)

// unlockTableState 是测试页表格的排序与选择状态。
var unlockTableState = ui.ListState{}

// pageUnlock 是「测试」页：检测各流媒体平台的解锁状态。
//
// 四列表格：平台 / 状态 / 检测时间 / 全部检测。
// 「全部检测」按钮直接放在表头第四列，不再单独占一行。
func (a *App) pageUnlock(c *ui.Context) {
	ui.Column(c).Fill().Padding(spaceLg).Children(func() {
		items := append([]unlock.Item(nil), a.UnlockItems...)
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

		state := unlockTableState
		state.HeaderCell = func(cell ui.Element, col int) {
			if col != 3 || a.UnlockChecking {
				return
			}
			// 表头高度有限，用紧凑按钮而不是主按钮。
			cell.Children(func() {
				btn := ui.Box(c).Padding(3, 10).Radius(radiusSm).
					LinearGradient(accentGradient(c.Theme().Accent)).
					Children(func() {
						text(c, "全部检测").FontSize(11).Bold().TextColor(c.Theme().AccentText)
					})
				btn.Cursor(ui.CursorPointer)
				if btn.Clicked() {
					a.checkAllUnlock()
				}
			})
		}

		ui.Table(c, &state, []ui.TableColumn{
			{Title: "平台", ID: "name", Width: 200, Sortable: true},
			{Title: "状态", ID: "status", Width: 120, Sortable: true},
			{Title: "检测时间", ID: "time", Width: 180, Sortable: true},
			{Title: "", ID: "act", Width: 130},
		}, len(items), func(row, col int) {
			it := items[row]
			switch col {
			case 0:
				text(c, it.Name).FontSize(13).SingleLine()
			case 1:
				label, fg := unlockStatusLabel(it.Status)
				text(c, label).FontSize(13).TextColor(fg).SingleLine()
			case 2:
				// 未检测时用 "-" 占位，不留空。
				when := it.CheckTime
				if when == "" {
					when = "-"
				}
				text(c, when).FontSize(11).TextColor(ui.Hex(textTertiary)).SingleLine()
			case 3:
				if !a.UnlockChecking {
					pillButton(c, "检测", "单独检测 "+it.Name, func() { a.checkUnlockItem(it.Name) })
				}
			}
		}).Grow(1).
			Background(c.Theme().Surface).
			Radius(radiusMd)
	})
}

// unlockStatusLabel 把后端状态翻译成显示用的文字与颜色。
//
// 状态只有三种：
//   - "-"：还没有检测过
//   - "检测中"：正在检测
//   - "Yes" / "No"：检测结果（失败也算 No，不暴露 Failed 这种技术词）
func unlockStatusLabel(status string) (string, ui.Color) {
	switch {
	case status == "" || strings.EqualFold(status, "Pending"):
		return "-", ui.Hex(textTertiary)
	case status == "检测中":
		return "检测中", ui.Hex(colorInfo)
	case strings.HasPrefix(status, "Yes"):
		return "Yes", ui.Hex(colorSuccess)
	case strings.HasPrefix(status, "No"):
		return "No", ui.Hex(colorDanger)
	case strings.HasPrefix(status, "Failed"):
		// 检测失败对用户来说就是“不可用”，不暴露 Failed 这种词。
		return "No", ui.Hex(colorDanger)
	default:
		return status, ui.Hex(textTertiary)
	}
}

func (a *App) unlockChecker() *unlock.Checker {
	return unlock.New(a.Settings.MixedPort)
}

func (a *App) checkAllUnlock() {
	a.UnlockChecking = true
	// 先把所有项标为“检测中”，让用户看到进度而不是空白。
	a.win.Update(func() {
		for i := range a.UnlockItems {
			a.UnlockItems[i].Status = "检测中"
		}
	})
	go func() {
		checker := a.unlockChecker()
		results := checker.CheckAll(context.Background(), func(item unlock.Item) {
			a.win.Update(func() {
				for i := range a.UnlockItems {
					if a.UnlockItems[i].Name == item.Name {
						a.UnlockItems[i] = item
					}
				}
			})
		})
		a.win.Update(func() {
			a.UnlockChecking = false
			a.UnlockItems = results
		})
	}()
}

func (a *App) checkUnlockItem(name string) {
	// 单项检测：先把这一项标为“检测中”。
	a.win.Update(func() {
		for i := range a.UnlockItems {
			if a.UnlockItems[i].Name == name {
				a.UnlockItems[i].Status = "检测中"
			}
		}
	})
	go func() {
		item := a.unlockChecker().Check(context.Background(), name)
		a.win.Update(func() {
			for i := range a.UnlockItems {
				if a.UnlockItems[i].Name == name {
					a.UnlockItems[i] = item
				}
			}
		})
	}()
}
