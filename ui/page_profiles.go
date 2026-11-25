package ui

import (
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/paths"
)

func (a *App) pageProfiles(c *ui.Context) {
	ui.Column(c).Fill().Padding(spaceLg).Gap(spaceMd).Children(func() {
		// 顶部一行：导入订阅 + 更新全部。
		ui.Row(c).Gap(spaceSm).AlignItems(ui.Center).Children(func() {
			primaryButton(c, a.tr("import_sub"), func() { a.openSubscriptionDialog() })
			pillButton(c, "更新全部", "重新下载所有远程订阅", func() { a.refreshAllProfiles() })
			ui.Spacer(c).Grow(1)
		})

		ui.Scroll(c).Grow(1).Gap(spaceSm).Children(func() {
			for _, item := range a.Profiles.DB.Items {
				it := item
				selected := a.Profiles.DB.Current == it.UID
				card(c, func() {
					ui.Row(c).AlignItems(ui.Center).Gap(12).Children(func() {
						ui.Icon(c, iconProfile).FontSize(22).TextColor(c.Theme().Accent)
						ui.Column(c).Grow(1).Gap(2).Children(func() {
							text(c, it.Name).Bold().FontSize(15)
							typeLabel := "本地"
							if it.Type == "remote" {
								typeLabel = "订阅"
							}
							updated := time.Unix(it.Updated, 0).Format("01-02 15:04")
							text(c, fmt.Sprintf("%s · 更新于 %s", typeLabel, updated)).
								FontSize(11).TextColor(c.Theme().TextMuted)
							if it.Extra != nil && it.Extra.Total > 0 {
								used := it.Extra.Download + it.Extra.Upload
								text(c, fmt.Sprintf("流量 %s / %s", humanBytes(used), humanBytes(it.Extra.Total))).
									FontSize(11).TextColor(c.Theme().TextMuted)
								pct := float64(used) / float64(it.Extra.Total)
								if pct > 1 {
									pct = 1
								}
								ui.Progress(c, pct).Height(4)
								if it.Extra.Expire > 0 {
									text(c, "到期 "+time.Unix(it.Extra.Expire, 0).Format("2006-01-02")).
										FontSize(11).TextColor(c.Theme().TextMuted)
								}
							}
						})
						if selected {
							ui.Badge(c, "使用中").Padding(4, 8)
						} else if ui.Button(c, a.tr("use")).Clicked() {
							a.useProfile(it.UID)
						}
						if ui.Button(c, a.tr("edit")).Clicked() {
							a.openEditor(it.UID)
						}
						if ui.Button(c, "扩展").Clicked() {
							a.openAttachments(it.UID)
						}
						if it.Type == "remote" && ui.Button(c, a.tr("update")).Clicked() {
							a.refreshProfile(it.UID)
						}
						if ui.Button(c, "").Width(28).Height(28).Padding(0).Center().Children(func() {
							ui.Icon(c, iconTrash).FontSize(15).TextColor(c.Theme().Danger)
						}).Clicked() && !selected {
							a.deleteProfile(it.UID)
						}
					})
				})
			}
			if len(a.Profiles.DB.Items) == 0 {
				card(c, func() {
					text(c, "还没有配置").Bold()
					text(c, "点击右上角「导入订阅」添加一个 Clash 订阅。").TextColor(c.Theme().TextMuted)
				})
			}
		})

		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, a.trs("打开数据目录")).Clicked() {
				openPath(paths.Home)
			}
		})
	})
}

func (a *App) useProfile(uid string) {
	if err := a.Profiles.Select(uid); err != nil {
		a.notify("错误", err.Error())
		return
	}
	a.refreshProfileTimer()
	a.reapplyCore()
}

func (a *App) refreshProfile(uid string) {
	go func() {
		if err := a.Profiles.Refresh(uid); err != nil {
			a.win.Update(func() { a.notify("更新失败", err.Error()) })
			return
		}
		a.win.Update(func() {
			if a.Profiles.DB.Current == uid {
				a.reapplyCore()
			}
			a.notify("更新成功", "订阅已更新")
		})
	}()
}

func (a *App) deleteProfile(uid string) {
	if err := a.checkWritable("删除配置"); err != nil {
		a.notify("只读模式", err.Error())
		return
	}
	if err := a.Profiles.Delete(uid); err != nil {
		a.notify("错误", err.Error())
		return
	}
	a.refreshProfileTimer()
	a.reapplyCore()
}
