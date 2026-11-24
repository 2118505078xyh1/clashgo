package ui

import (
	"fmt"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
	"clashgo/internal/profile"
)

// Attachment dialog state.
var attachKinds = []struct {
	kind  config.ProfileType
	label string
}{
	{config.ProfileMerge, "Merge 合并"},
	{config.ProfileRules, "Rules 规则"},
	{config.ProfileProxies, "Proxies 节点"},
	{config.ProfileGroups, "Groups 代理组"},
}

func (a *App) openAttachments(uid string) {
	a.AttachParent = uid
	a.AttachDialog = true
}

func (a *App) overlayAttachments(c *ui.Context) {
	ui.Modal(c, &a.AttachDialog, func() {
		ui.Column(c).Width(720).Height(560).Padding(20).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			text(c, "配置增强附件").FontSize(18).Bold()
			text(c, "附件按顺序执行：Seq(rules/proxies/groups) → Merge。").
				FontSize(12).TextColor(c.Theme().TextMuted)

			parent := a.Profiles.DB.Find(a.AttachParent)
			if parent == nil {
				a.AttachDialog = false
				return
			}
			opt := parent.Option
			for _, ak := range attachKinds {
				uid := profile.AttachmentUID(opt, ak.kind)
				var attached *config.PrfItem
				if uid != "" {
					attached = a.Profiles.DB.Find(uid)
				}
				ui.Row(c).Gap(8).Padding(6, 0).AlignItems(ui.Center).Children(func() {
					text(c, ak.label).Width(130)
					if attached != nil {
						text(c, fmt.Sprintf("%s (%s)", attached.Name, attached.UID)).Grow(1)
						if ui.Button(c, "编辑").Clicked() {
							a.EditorUID = attached.UID
							a.EditorContent = readAttachmentContent(a, attached)
							a.EditorOpen = true
						}
						if ui.Button(c, "移除").Clicked() {
							a.removeAttachment(parent, ak.kind)
						}
					} else {
						text(c, "未设置").Grow(1).TextColor(c.Theme().TextMuted)
						if ui.Button(c, "创建").Clicked() {
							a.createAttachment(parent, ak.kind)
						}
					}
				})
			}
			ui.Row(c).Justify(ui.End).Children(func() {
				if ui.Button(c, "关闭").Clicked() {
					a.AttachDialog = false
				}
			})
		})
	})
}

func readAttachmentContent(a *App, item *config.PrfItem) string {
	b, err := a.Profiles.Content(item)
	if err != nil {
		return ""
	}
	return string(b)
}

func (a *App) createAttachment(parent *config.PrfItem, kind config.ProfileType) {
	content, name := "", ""
	switch kind {
	case config.ProfileMerge:
		content, name = profile.MergeTemplate, "合并配置"
	case config.ProfileScript:
		content, name = profile.ScriptTemplate, "扩展脚本"
	default:
		content, name = profile.SeqTemplate, "序列 "+string(kind)
	}
	item, err := a.Profiles.CreateAttachment(parent.UID, kind, name, content)
	if err != nil {
		a.notify("错误", err.Error())
		return
	}
	// Open the new attachment in the editor immediately.
	a.EditorUID = item.UID
	a.EditorContent = content
	a.EditorOpen = true
	if parent.UID == a.Profiles.DB.Current {
		a.reapplyCore()
	}
}

func (a *App) removeAttachment(parent *config.PrfItem, kind config.ProfileType) {
	uid := profile.AttachmentUID(parent.Option, kind)
	if uid == "" {
		return
	}
	_ = a.Profiles.Delete(uid)
	switch kind {
	case config.ProfileMerge:
		parent.Option.Merge = ""
	case config.ProfileScript:
		parent.Option.Script = ""
	case config.ProfileRules:
		parent.Option.Rules = ""
	case config.ProfileProxies:
		parent.Option.Proxies = ""
	case config.ProfileGroups:
		parent.Option.Groups = ""
	}
	_ = a.Profiles.Save()
	if parent.UID == a.Profiles.DB.Current {
		a.reapplyCore()
	}
}
