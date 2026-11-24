package ui

import (
	"fmt"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/paths"
	"clashgo/internal/resources"
)

// Resource dialog state. It lives at package level on purpose: the main app
// struct must not be touched just to host this optional overlay.
var (
	resourcesOpen bool
	resourcesList []resources.ResourceInfo
)

// ShowResources opens the resource manager dialog.
func (a *App) ShowResources() {
	resourcesList = resources.List(paths.Home)
	resourcesOpen = true
}

// showResources is a short alias kept for callers that prefer the lowercase
// spelling.
func (a *App) showResources() { a.ShowResources() }

// showResources opens the dialog without needing an App receiver.
func showResources() {
	resourcesList = resources.List(paths.Home)
	resourcesOpen = true
}

func (a *App) overlayResources(c *ui.Context) {
	if resourcesList == nil {
		resourcesList = resources.List(paths.Home)
	}
	ui.Modal(c, &resourcesOpen, func() {
		t := c.Theme()
		ui.Column(c).Width(640).Height(520).Padding(20).Gap(12).
			Background(t.Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "规则资源更新").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					resourcesOpen = false
				}
			})
			text(c, "资源文件存放于 "+paths.Home).FontSize(11).TextColor(t.TextMuted)
			if ui.Button(c, "刷新状态").Clicked() {
				resourcesList = resources.List(paths.Home)
			}
			ui.List(c, nil, len(resourcesList), func(i int) {
				r := resourcesList[i]
				ui.Row(c).Gap(8).Padding(7, 8).AlignItems(ui.Center).Children(func() {
					text(c, r.Name).Bold().Width(110)
					text(c, r.File).FontSize(11).TextColor(t.TextMuted).Grow(1)
					if r.Installed {
						ui.Badge(c, "已安装").Padding(3, 8).TextColor(t.Success)
						text(c, humanSize(r.Size)).FontSize(11).TextColor(t.TextMuted).Width(80)
						text(c, r.ModTime.Format("01-02 15:04")).FontSize(11).
							TextColor(t.TextMuted).Width(88)
					} else {
						ui.Badge(c, "未安装").Padding(3, 8).TextColor(t.TextMuted)
						text(c, "").Grow(1)
					}
					if ui.Button(c, "下载").Clicked() {
						r := r
						go func() {
							err := resources.Download(paths.Home, r.File, r.URL)
							a.win.Update(func() {
								resourcesList = resources.List(paths.Home)
								if err != nil {
									a.notify("资源下载失败", r.Name+"："+err.Error())
								} else {
									a.notify("资源下载完成", r.Name+" 已安装")
								}
							})
						}()
					}
					if r.Installed {
						if ui.Button(c, "删除").Clicked() {
							r := r
							if err := resources.Delete(paths.Home, r.File); err != nil {
								a.notify("资源删除失败", err.Error())
								return
							}
							resourcesList = resources.List(paths.Home)
							a.notify("资源已删除", r.Name)
						}
					}
				})
			}).Grow(1).Background(t.Background).Radius(10)
			text(c, "下载先写入临时文件，完成后原子替换；失败不会影响已安装的资源。").
				FontSize(11).TextColor(t.TextMuted)
		})
	})
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprint(n) + " B"
	}
	v := float64(n)
	for _, u := range []string{"KB", "MB", "GB"} {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f TB", v/unit)
}
