package ui

import "clashgo/internal/profile"

// startProfileTimer 启动订阅定时自动更新（对齐 Clash Verge 的 timer）。
// 定时更新完成后，若更新的是当前订阅则重新应用内核配置，并发通知。
func (a *App) startProfileTimer() {
	a.ProfileTimer = profile.NewTimer(a.Profiles, func(uid string, err error) {
		a.win.Update(func() {
			if err != nil {
				a.notify("订阅自动更新失败", err.Error())
				return
			}
			if a.Profiles.DB.Current == uid {
				a.reapplyCore()
			}
			a.notify("订阅已自动更新", a.profileName(uid))
			// 更新后按新 Updated 时间重新排期。
			a.ProfileTimer.Refresh()
		})
	})
	a.ProfileTimer.Start()
}

// refreshProfileTimer 在订阅增删改后重新排期（timer 尚未启动时无操作）。
func (a *App) refreshProfileTimer() {
	if a.ProfileTimer != nil {
		a.ProfileTimer.Refresh()
	}
}

// profileName 返回订阅显示名（找不到时返回 uid）。
func (a *App) profileName(uid string) string {
	if item := a.Profiles.DB.Find(uid); item != nil {
		return item.Name
	}
	return uid
}
