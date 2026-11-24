package ui

import (
	"context"
	"time"

	"clashgo/internal/notice"
	"clashgo/internal/updater"
)

// startAutoUpdateCheck performs a background update check shortly after
// startup if auto-check is enabled (idea from common practice).
func (a *App) startAutoUpdateCheck() {
	if !a.Settings.AutoCheckUpdate {
		return
	}
	go func() {
		// Give the UI a moment to settle before checking.
		time.Sleep(10 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		rel, err := updater.New().Latest(ctx)
		if err != nil {
			return // silent failure for auto-check
		}
		if updater.Compare(rel.TagName, "v1.0.0") > 0 {
			a.win.Update(func() {
				a.LatestRelease = rel
				a.Notices.Push(updaterCodeUpdate, "发现新版本 "+rel.TagName, notice.Success)
			})
		}
	}()
}

const updaterCodeUpdate = "update::available"
