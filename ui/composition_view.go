package ui

import (
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
)

func (a *App) overlayComposition(c *ui.Context) {
	ui.Modal(c, &a.CompositionOpen, func() {
		ui.Column(c).Width(520).Height(520).Padding(24).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			text(c, "新建节点池（多订阅合并）").FontSize(18).Bold()
			text(c, "选择一个基础订阅 + 若干贡献订阅，把它们的节点合并成一个配置。").
				FontSize(11).TextColor(c.Theme().TextMuted)
			ui.TextInput(c, &a.CompositionName).Placeholder("名称，如：全部节点")

			// Config profiles (non-attachment) as base + contributors.
			var configs []*config.PrfItem
			for _, it := range a.Profiles.DB.Items {
				switch it.Type {
				case config.ProfileLocal, config.ProfileRemote:
					configs = append(configs, it)
				}
			}
			baseSel := a.CompositionBase
			if baseSel == "" && len(configs) > 0 {
				baseSel = configs[0].Name
			}
			var names []string
			for _, it := range configs {
				names = append(names, it.Name)
			}
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				text(c, "基础订阅").Width(80)
				ui.Combobox(c, &baseSel, names).Grow(1)
			})
			// Track selection by name (simplify: store name in CompositionBase).
			if baseSel != a.CompositionBase {
				a.CompositionBase = baseSel
			}

			text(c, "贡献订阅（勾选要合并节点的订阅）").FontSize(12)
			ui.Scroll(c).Grow(1).Gap(2).Children(func() {
				contribSet := map[string]bool{}
				for _, s := range strings.Split(a.CompositionContrib, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						contribSet[s] = true
					}
				}
				for _, it := range configs {
					name := it.Name
					checked := contribSet[name]
					if ui.Checkbox(c, &checked, name).Changed() {
						if checked {
							contribSet[name] = true
						} else {
							delete(contribSet, name)
						}
						var list []string
						for k := range contribSet {
							list = append(list, k)
						}
						a.CompositionContrib = strings.Join(list, ",")
					}
				}
			})
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.CompositionOpen = false
				}
				if ui.PrimaryButton(c, "创建").Clicked() {
					a.createComposition(a.CompositionBase, strings.Split(a.CompositionContrib, ","))
				}
			})
		})
	})
}

// nameToUID resolves a profile name to its UID.
func (a *App) nameToUID(name string) string {
	for _, it := range a.Profiles.DB.Items {
		if it.Name == strings.TrimSpace(name) {
			return it.UID
		}
	}
	return ""
}

func (a *App) createComposition(baseName string, contribNames []string) {
	name := strings.TrimSpace(a.CompositionName)
	if name == "" {
		a.notify("错误", "请输入名称")
		return
	}
	baseUID := a.nameToUID(baseName)
	var contribUIDs []string
	for _, n := range contribNames {
		if uid := a.nameToUID(n); uid != "" && uid != baseUID {
			contribUIDs = append(contribUIDs, uid)
		}
	}
	if _, err := a.Profiles.CreateComposition(name, baseUID, contribUIDs); err != nil {
		a.notify("创建失败", err.Error())
		return
	}
	a.CompositionOpen = false
	a.reapplyCore()
	a.notify("创建成功", "节点池 "+name+" 已创建并应用")
}
