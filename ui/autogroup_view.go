package ui

import (
	"fmt"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/autogroup"
)

// generateRegionGroups builds region groups from all known node names.
func (a *App) generateRegionGroups() {
	var nodes []string
	seen := map[string]bool{}
	for _, p := range a.Proxies {
		for _, n := range p.All {
			if n != "" && !seen[n] {
				seen[n] = true
				nodes = append(nodes, n)
			}
		}
	}
	// Also include standalone nodes (not in any group).
	for name, p := range a.Proxies {
		if !p.Group && name != "DIRECT" && name != "REJECT" && !seen[name] {
			nodes = append(nodes, name)
		}
	}
	a.AutoGroups = autogroup.Build(nodes)
	a.AutoGroupsOpen = true
}

func (a *App) overlayAutoGroups(c *ui.Context) {
	ui.Modal(c, &a.AutoGroupsOpen, func() {
		ui.Column(c).Width(560).Height(560).Padding(20).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "按地区自动建组").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					a.AutoGroupsOpen = false
				}
			})
			text(c, "根据节点名称中的地区关键词自动分组，带流量/到期字样的节点已排除").
				FontSize(11).TextColor(c.Theme().TextMuted)
			ui.Scroll(c).Grow(1).Gap(6).Children(func() {
				if len(a.AutoGroups) == 0 {
					text(c, "没有识别到地区节点").TextColor(c.Theme().TextMuted)
				}
				for _, g := range a.AutoGroups {
					gg := g
					card(c, func() {
						ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
							text(c, autogroup.GroupName(gg)).Bold().Width(140)
							text(c, fmt.Sprint(len(gg.Members))).FontSize(12).TextColor(c.Theme().TextMuted).Width(40)
							text(c, firstN(gg.Members, 3)).FontSize(11).Grow(1).TextColor(c.Theme().TextMuted)
						})
					})
				}
			})
		})
	})
}

func firstN(s []string, n int) string {
	if len(s) == 0 {
		return ""
	}
	if len(s) > n {
		s = s[:n]
	}
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	if len(out) > 60 {
		out = out[:60] + "..."
	}
	return out
}
