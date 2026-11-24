package ui

import (
	"fmt"
	"sort"

	"github.com/egoist/mygo/ui"
)

// ruleHits aggregates active-connection traffic by rule (type|payload).
func (a *App) ruleHits() map[string]int64 {
	hits := map[string]int64{}
	for _, conn := range a.Connections {
		key := conn.Rule + "|" + conn.RulePayload
		hits[key] += conn.Download + conn.Upload
	}
	return hits
}

func (a *App) pageRules(c *ui.Context) {
	hits := a.ruleHits()
	var filtered []map[string]any
	filter := a.Search
	for _, r := range a.Rules {
		typeName, _ := r["type"].(string)
		payload, _ := r["payload"].(string)
		proxy, _ := r["proxy"].(string)
		if a.RuleTypeFilter != "" && !containsFold(typeName, a.RuleTypeFilter) {
			continue
		}
		if filter != "" && !containsFold(payload, filter) && !containsFold(proxy, filter) && !containsFold(typeName, filter) {
			continue
		}
		filtered = append(filtered, r)
	}
	if a.RuleSortByHits {
		sort.SliceStable(filtered, func(i, j int) bool {
			ki := fmt.Sprint(filtered[i]["type"], "|", filtered[i]["payload"])
			kj := fmt.Sprint(filtered[j]["type"], "|", filtered[j]["payload"])
			return hits[ki] > hits[kj]
		})
	}

	ui.Column(c).Fill().Padding(24).Gap(12).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			text(c, a.tr("rules")).FontSize(24).Bold().Grow(1)
			ui.TextInput(c, &a.Search).Placeholder("搜索规则…").Width(200)
			typeSel := a.RuleTypeFilter
			types := []string{"", "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "GEOIP", "GEOSITE", "PROCESS-NAME", "MATCH"}
			ui.Combobox(c, &typeSel, types).Width(150).Placeholder("全部类型")
			if typeSel != a.RuleTypeFilter {
				a.RuleTypeFilter = typeSel
			}
			if ui.Button(c, "按命中流量排序").Clicked() {
				a.RuleSortByHits = !a.RuleSortByHits
			}
			text(c, fmt.Sprintf("%d / %d", len(filtered), len(a.Rules))).TextColor(c.Theme().TextMuted)
		})

		ui.List(c, nil, len(filtered), func(i int) {
			r := filtered[i]
			typeName, _ := r["type"].(string)
			payload, _ := r["payload"].(string)
			proxy, _ := r["proxy"].(string)
			key := fmt.Sprint(typeName, "|", payload)
			ui.Row(c).Gap(12).Padding(8, 12).Children(func() {
				if ui.Button(c, "→").Width(30).Tooltip("查看该规则的连接").Clicked() {
					a.RuleJumpFilter = payload
					a.Search = ""
					a.router.Push("/connections")
				}
				ui.Badge(c, typeName).Width(110)
				text(c, payload).Grow(1)
				if a.RuleSortByHits && hits[key] > 0 {
					text(c, humanBytes(hits[key])).Width(80).TextColor(c.Theme().TextMuted)
				}
				text(c, proxy).TextColor(c.Theme().Accent).Width(160)
			})
		}).Grow(1).Background(c.Theme().Surface).Radius(10)
	})
}
