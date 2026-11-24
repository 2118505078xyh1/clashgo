package ui

import (
	"github.com/egoist/mygo/ui"
)

// needsOnboarding 判断用户是否还没导入任何可用配置。
// 默认配置（空配置、无节点）视为未完成初始化。
func (a *App) needsOnboarding() bool {
	item := a.Profiles.DB.CurrentItem()
	if item == nil {
		return true
	}
	// 远程订阅视为已导入；本地"默认配置"且无节点视为未初始化。
	if item.Type == "remote" {
		return false
	}
	if len(a.groupNames()) > 0 {
		return false
	}
	return item.Name == "默认配置"
}

// onboardingBanner 在首页顶部显示三步引导，导入订阅后自动消失。
func (a *App) onboardingBanner(c *ui.Context) {
	if !a.needsOnboarding() {
		return
	}
	t := c.Theme()
	b := ui.Column(c).FillWidth().Gap(10).Padding(16).Radius(14).
		Background(withAlpha(t.Accent, 0.12)).Border(1, withAlpha(t.Accent, 0.35))
	b.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Image(c, logoBitmap).Size(20, 20)
			text(c, "欢迎使用 ClashGo，3 步开始").FontSize(15).Bold().Grow(1)
		})
		text(c, "① 导入订阅地址  →  ② 在代理页选节点  →  ③ 打开系统代理").FontSize(12).TextColor(t.Text)
		ui.Row(c).Gap(10).Children(func() {
			if ui.PrimaryButton(c, "① 立即导入订阅").Clicked() {
				a.openSubscriptionDialog()
			}
			if ui.Button(c, "我已有配置，跳过").Clicked() {
				a.Settings.OnboardingDone = true
				a.mustSaveSettings()
			}
		})
	})
}
