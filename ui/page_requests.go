package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
)

// pageRequests shows a recent-request history (closed + active) aggregated
// from the connection stream, similar to common practice).
func (a *App) pageRequests(c *ui.Context) {
	var filtered []config.ConnectionView
	for _, r := range a.Requests {
		if a.Search != "" && !containsFold(r.Host, a.Search) &&
			!containsFold(r.Process, a.Search) && !containsFold(r.RulePayload, a.Search) {
			continue
		}
		filtered = append(filtered, r)
	}
	// Newest first.
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Start > filtered[j].Start })

	ui.Column(c).Fill().Padding(24).Gap(12).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			text(c, "请求记录").FontSize(24).Bold().Grow(1)
			ui.TextInput(c, &a.Search).Placeholder("搜索域名/进程…").Width(220)
			text(c, fmt.Sprintf("%d 条", len(filtered))).TextColor(c.Theme().TextMuted)
			if ui.Button(c, "清空").Clicked() {
				a.Requests = nil
				a.ActiveReqIDs = map[string]int{}
			}
		})

		ui.List(c, nil, len(filtered), func(i int) {
			r := filtered[i]
			ui.Row(c).Gap(10).Padding(6, 12).AlignItems(ui.Center).Children(func() {
				text(c, r.Start).FontSize(10).TextColor(c.Theme().TextMuted).Width(60)
				host := r.Host
				if host == "" {
					host = r.DestinationIP
				}
				text(c, host).Grow(1)
				text(c, r.Process).FontSize(11).TextColor(c.Theme().TextMuted).Width(120)
				ui.Badge(c, strings.ToUpper(r.Network)).Width(50)
				text(c, r.RulePayload).FontSize(11).Width(120).TextColor(c.Theme().TextMuted)
				text(c, humanBytes(r.Download+r.Upload)).Width(80)
			})
		}).Grow(1).Background(c.Theme().Surface).Radius(10)
	})
}
