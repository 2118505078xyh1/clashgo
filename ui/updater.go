package ui

import (
	"context"
	"time"

	"clashgo/internal/updater"
)

func (a *App) checkUpdate() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		rel, err := updater.New().Latest(ctx)
		a.win.Update(func() {
			if err != nil {
				a.notify("检查更新失败", err.Error())
				return
			}
			a.LatestRelease = rel
			cmp := updater.Compare(rel.TagName, "v1.0.0")
			if cmp > 0 {
				a.notify("发现新版本", rel.TagName+"\n"+rel.Name)
			} else {
				a.notify("已是最新版", "当前 v1.0.0，最新 "+rel.TagName)
			}
		})
	}()
}
