package ui

import (
	"fmt"

	"clashgo/internal/notice"
)

// refreshAllProfiles updates all remote subscriptions sequentially,
// reporting per-item results (idea from common practice).
func (a *App) refreshAllProfiles() {
	var remote []string
	for _, item := range a.Profiles.DB.Items {
		if item.Type == "remote" {
			remote = append(remote, item.UID)
		}
	}
	if len(remote) == 0 {
		a.notify("提示", "没有远程订阅需要更新")
		return
	}
	go func() {
		ok, failed := 0, 0
		var failures []string
		for _, uid := range remote {
			item := a.Profiles.DB.Find(uid)
			if err := a.Profiles.Refresh(uid); err != nil {
				failed++
				failures = append(failures, item.Name+": "+err.Error())
			} else {
				ok++
			}
		}
		a.win.Update(func() {
			if a.Profiles.DB.Current != "" {
				a.reapplyCore()
			}
			msg := fmt.Sprintf("更新完成：成功 %d，失败 %d", ok, failed)
			if failed > 0 {
				msg += "\n" + joinLines(failures)
			}
			level := notice.Success
			if failed > 0 {
				level = notice.Warning
			}
			a.Notices.Push("profile::update_all", msg, level)
			a.DialogTitle, a.DialogBody, a.DialogOpen = "批量更新", msg, true
		})
	}()
}

func joinLines(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += "\n"
		}
		out += x
	}
	return out
}
