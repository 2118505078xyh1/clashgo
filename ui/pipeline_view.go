package ui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
)

// overlayPipeline shows the enhancement pipeline steps and which top-level
// keys each stage changed (lightweight config-inspector, a reference GUI style).
func (a *App) overlayPipeline(c *ui.Context) {
	ui.Modal(c, &a.PipelineOpen, func() {
		ui.Column(c).Width(640).Height(520).Padding(20).Gap(12).
			Background(c.Theme().Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "配置增强过程").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					a.PipelineOpen = false
				}
			})
			text(c, "按顺序展示每一步改动的顶层字段，便于排查配置问题").
				FontSize(11).TextColor(c.Theme().TextMuted)
			ui.Scroll(c).Grow(1).Gap(6).Children(func() {
				if len(a.PipelineSteps) == 0 {
					text(c, "暂无步骤记录，重载配置后可见").TextColor(c.Theme().TextMuted)
				}
				for i, step := range a.PipelineSteps {
					st := step
					card(c, func() {
						ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
							ui.Badge(c, itoaLocal(i+1)).Width(30)
							text(c, st.Name).Bold().Grow(1)
							text(c, fmt.Sprint(len(st.ChangedKeys))).TextColor(c.Theme().TextMuted).Width(30)
						})
						changed := strings.Join(st.ChangedKeys, ", ")
						if changed == "" {
							changed = "（无变化）"
						}
						text(c, changed).FontSize(11).TextColor(c.Theme().TextMuted)
					})
				}
			})
		})
	})
}
