package ui

import (
	"context"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/unlock"
)

func (a *App) pageUnlock(c *ui.Context) {
	ui.Column(c).Fill().Padding(20).Gap(12).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			text(c, a.tr("unlock")).FontSize(22).Bold().Grow(1)
			text(c, "通过本地代理检测各平台解锁状态与地区").TextColor(c.Theme().TextMuted).FontSize(12)
			if a.UnlockChecking {
				ui.Button(c, "检测中...").Disabled(true)
			} else if ui.PrimaryButton(c, a.trs("全部检测")).Clicked() {
				a.checkAllUnlock()
			}
		})

		ui.Scroll(c).Grow(1).Gap(8).Children(func() {
			items := append([]unlock.Item(nil), a.UnlockItems...)
			sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
			for _, item := range items {
				it := item
				card(c, func() {
					ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
						text(c, it.Name).Bold().FontSize(14).Width(180)
						statusColor := c.Theme().TextMuted
						switch {
						case it.Status == "Yes" || strings.HasPrefix(it.Status, "Yes"):
							statusColor = c.Theme().Success
						case it.Status == "No" || strings.Contains(it.Status, "Failed"):
							statusColor = c.Theme().Danger
						case it.Status == "Soon" || it.Status == "Risky" || it.Status == "Originals Only":
							statusColor = c.Theme().Warning
						}
						text(c, it.Status).TextColor(statusColor).Grow(1)
						if it.Region != "" {
							text(c, it.Region).Width(100)
						}
						text(c, it.CheckTime).FontSize(11).TextColor(c.Theme().TextMuted).Width(140)
						if !a.UnlockChecking && ui.Button(c, a.trs("检测")).Clicked() {
							a.checkUnlockItem(it.Name)
						}
					})
				})
			}
		})
	})
}

func (a *App) unlockChecker() *unlock.Checker {
	return unlock.New(a.Settings.MixedPort)
}

func (a *App) checkAllUnlock() {
	a.UnlockChecking = true
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
