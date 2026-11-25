package ui

import (
	"github.com/egoist/mygo/ui"

	"clashgo/internal/dnsq"
)

func (a *App) pageDNS(c *ui.Context) {
	ui.Column(c).Fill().Padding(spaceLg).Gap(spaceMd).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			text(c, a.tr("dns")).FontSize(24).Bold().Grow(1)
			ui.TextInput(c, &a.Search).Placeholder("搜索域名…").Width(220)
			if ui.Button(c, a.trs("清空")).Clicked() {
				a.DNSRecords = nil
			}
		})
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			text(c, "主动查询").FontSize(12)
			ui.TextInput(c, &a.DNSQueryName).Placeholder("example.com").Width(220)
			if ui.Button(c, "查询").Clicked() {
				a.queryDNS()
			}
			if a.DNSQueryResult != "" {
				text(c, a.DNSQueryResult).TextColor(c.Theme().Accent)
			}
		})
		text(c, a.trs("实时解析记录（来自内核日志，需将日志级别设为 debug）")).
			FontSize(12).TextColor(c.Theme().TextMuted)

		var records []dnsq.Record
		for _, r := range a.DNSRecords {
			if a.Search != "" && !containsFold(r.Domain, a.Search) && !containsFold(r.Answer, a.Search) {
				continue
			}
			records = append(records, r)
		}
		ui.List(c, nil, len(records), func(i int) {
			r := records[i]
			color := c.Theme().TextMuted
			switch r.Type {
			case "hit":
				color = c.Theme().Warning
			case "resolve":
				color = c.Theme().Success
			case "error":
				color = c.Theme().Danger
			}
			ui.Row(c).Gap(10).Padding(7, 12).AlignItems(ui.Center).Children(func() {
				text(c, r.Time).FontSize(11).TextColor(c.Theme().TextMuted).Width(70)
				ui.Badge(c, r.Type).Width(60)
				text(c, r.Domain).Grow(1)
				text(c, r.Answer).Width(220).TextColor(color)
				if r.Server != "" {
					text(c, r.Server).FontSize(11).TextColor(c.Theme().TextMuted).Width(140)
				}
			})
		}).Grow(1).Background(c.Theme().Surface).Radius(10)
	})
}
