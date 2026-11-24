package ui

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
)

// pipelineDiffExpanded keeps the per-step expansion state of the full diff
// viewer. The UI is single-threaded, so a package-level map is sufficient.
var pipelineDiffExpanded = map[int]bool{}

// overlayPipelineFull renders the full a reference GUI-style pipeline inspector as a
// modal: a scrollable step list with per-step before/after JSON diff panes.
// It returns true when a modal was actually rendered, so the caller (wired in
// overlays()) can stop processing later overlays for this frame.
func (a *App) overlayPipelineFull(c *ui.Context) bool {
	if !a.PipelineOpen {
		return false
	}
	t := c.Theme()
	ui.Modal(c, &a.PipelineOpen, func() {
		ui.Column(c).Width(900).Height(640).Padding(20).Gap(12).
			Background(t.Surface).Radius(12).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				text(c, "配置增强 · 步骤与差异").FontSize(18).Bold().Grow(1)
				if ui.Button(c, "关闭").Clicked() {
					a.PipelineOpen = false
				}
			})
			text(c, fmt.Sprintf("共 %d 步 · 展开步骤可查看该步改动的顶层字段 before / after",
				len(a.PipelineSteps))).FontSize(11).TextColor(t.TextMuted)

			ui.List(c, nil, len(a.PipelineSteps), func(i int) {
				if i >= len(a.PipelineSteps) {
					return
				}
				st := a.PipelineSteps[i]
				card(c, func() {
					levelColor := t.Accent
					if st.Level == "warn" {
						levelColor = t.Warning
					}
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Badge(c, itoaLocal(i+1)).Width(34)
						text(c, st.Name).Bold().Grow(1)
						text(c, strings.ToUpper(st.Level)).FontSize(10).TextColor(levelColor)
						text(c, fmt.Sprint(len(st.ChangedKeys))).TextColor(t.TextMuted).Width(30)
					})
					changed := strings.Join(st.ChangedKeys, ", ")
					if changed == "" {
						changed = "（无变化）"
					}
					text(c, "改动字段: "+changed).FontSize(11).TextColor(t.TextMuted)

					if st.BeforeJSON == "" && st.AfterJSON == "" {
						return
					}
					expanded := pipelineDiffExpanded[i]
					label := "展开差异 ▾"
					if expanded {
						label = "收起差异 ▴"
					}
					if ui.Button(c, label).Clicked() {
						pipelineDiffExpanded[i] = !expanded
					}
					if !expanded {
						return
					}
					ui.Row(c).Gap(10).Children(func() {
						ui.Column(c).Grow(1).Gap(4).Children(func() {
							text(c, "修改前").FontSize(11).Bold().TextColor(t.Danger)
							text(c, st.BeforeJSON).Font("monospace").FontSize(11).TextColor(t.TextMuted)
						})
						ui.Column(c).Grow(1).Gap(4).Children(func() {
							text(c, "修改后").FontSize(11).Bold().TextColor(t.Success)
							text(c, st.AfterJSON).Font("monospace").FontSize(11).TextColor(t.Text)
						})
					})
				})
			}).Grow(1).Background(t.Surface).Radius(8)
		})
	})
	return true
}
