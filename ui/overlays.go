package ui

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

func (a *App) overlaysForImport(c *ui.Context) {
	ui.Modal(c, &a.ImportDialog, func() {
		ui.Column(c).Width(420).Padding(24).Gap(12).Background(c.Theme().Surface).Radius(12).Selectable().Children(func() {
			text(c, a.tr("import_sub")).FontSize(18).Bold()
			text(c, a.tr("name")).TextColor(c.Theme().TextMuted)
			ui.TextInput(c, &a.ImportName).Placeholder("例如：我的机场")
			text(c, a.tr("url")).TextColor(c.Theme().TextMuted)
			ui.TextInput(c, &a.PendingURL).Placeholder("https://...")
			ui.Checkbox(c, &a.BatchImport, "批量导入（每行一个订阅地址，自动去重）")
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, a.tr("cancel")).Clicked() {
					a.ImportDialog = false
				}
				if ui.PrimaryButton(c, "导入").Clicked() {
					a.doImport()
				}
			})
		})
	})
}

func (a *App) overlaysForEditor(c *ui.Context) {
	ui.Modal(c, &a.EditorOpen, func() {
		ui.Column(c).Width(720).Height(560).Padding(20).Gap(12).Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "编辑配置 YAML").FontSize(18).Bold().Grow(1)
				if ui.Button(c, a.tr("close")).Clicked() {
					a.EditorOpen = false
				}
			})
			text(c, "修改后点击保存，配置会经过 YAML 校验并自动重载内核。").
				FontSize(12).TextColor(c.Theme().TextMuted)
			ui.TextArea(c, &a.EditorContent).Grow(1)
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, a.tr("cancel")).Clicked() {
					a.EditorOpen = false
				}
				if ui.PrimaryButton(c, a.tr("save")).Clicked() {
					a.saveEditor()
				}
			})
		})
	})
}

func (a *App) overlays(c *ui.Context) {
	if a.DialogOpen {
		ui.Modal(c, &a.DialogOpen, func() {
			ui.Column(c).Width(360).Padding(24).Gap(16).Background(c.Theme().Surface).Radius(12).Children(func() {
				text(c, a.DialogTitle).FontSize(18).Bold()
				text(c, a.DialogBody).TextColor(c.Theme().TextMuted).Selectable()
				if ui.Button(c, "复制内容").Clicked() {
					mygo.Clipboard.WriteText(a.DialogTitle + "\n" + a.DialogBody)
				}
				if ui.Button(c, a.tr("ok")).Clicked() {
					a.DialogOpen = false
				}
			})
		})
	}
	if a.ImportDialog {
		a.overlaysForImport(c)
	}
	if a.EditorOpen {
		a.overlaysForEditor(c)
	}
	if a.RuntimeConfigOpen {
		a.overlayRuntimeConfig(c)
	}
	if a.AutoGroupsOpen {
		a.overlayAutoGroups(c)
	}
	if a.PipelineOpen {
		if a.overlayPipelineFull(c) {
			return
		}
		a.overlayPipeline(c)
	}
	if a.ColorPickerOpen {
		a.overlayColorPicker(c)
	}
	if a.CompositionOpen {
		a.overlayComposition(c)
	}
	if resourcesOpen {
		a.overlayResources(c)
	}
	if chainOpen {
		a.overlayProfileChain(c)
	}
	if safeOpen {
		a.overlaySafe(c)
	}
	if wingeoOpen {
		a.overlayWindowGeo(c)
	}
	if a.AttachDialog {
		a.overlayAttachments(c)
	}
}
