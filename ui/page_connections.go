package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
)

func (a *App) pageConnections(c *ui.Context) {
	t := c.Theme()
	// Filter first so the list has no blank rows. RuleJumpFilter (set when
	// clicking a rule's → button) filters connections by rule payload.
	jumpFilter := a.RuleJumpFilter
	var conns []config.ConnectionView
	for _, conn := range a.Connections {
		if jumpFilter != "" && !containsFold(conn.RulePayload, jumpFilter) && !containsFold(conn.Rule, jumpFilter) {
			continue
		}
		if a.Search != "" && !containsFold(conn.Host, a.Search) &&
			!containsFold(conn.Full, a.Search) && !containsFold(conn.Rule, a.Search) {
			continue
		}
		// 网络类型筛选（对齐 Clash Verge 的 All/TCP/UDP）
		if a.ConnNetworkFilter != "" && !strings.EqualFold(conn.Network, a.ConnNetworkFilter) {
			continue
		}
		conns = append(conns, conn)
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].Start > conns[j].Start })

	ui.Column(c).Fill().Padding(20).Gap(12).Children(func() {
		a.pageHeader(c, a.tr("connections"), nil)
		card(c, func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				if jumpFilter != "" {
					ui.Badge(c, "规则: "+jumpFilter)
					if ui.Button(c, "清除").Clicked() {
						a.RuleJumpFilter = ""
					}
				}
				ui.TextInput(c, &a.Search).Placeholder("搜索主机…").Width(180)
				// 网络类型切换（All / TCP / UDP）
				for _, nf := range []struct{ key, label string }{{"", "全部"}, {"tcp", "TCP"}, {"udp", "UDP"}} {
					fk := nf.key
					sel := a.ConnNetworkFilter == fk
					b := ui.Button(c, nf.label).Radius(6)
					if sel {
						b.Background(t.Accent).TextColor(t.AccentText)
					}
					if b.Clicked() {
						a.ConnNetworkFilter = fk
					}
				}
				text(c, fmt.Sprintf("%d / %d", len(conns), len(a.Connections))).TextColor(t.TextMuted)
				if ui.Button(c, a.trs("全部关闭")).Clicked() {
					go func() { _ = a.currentClient().CloseAllConnections() }()
				}
				ui.PopoverMenuButton(c, "⋮", func(m *ui.Menu) {
					if m.Item(a.trs("全部关闭")).Chosen() {
						go func() { _ = a.currentClient().CloseAllConnections() }()
					}
					if m.Item("导出").Chosen() {
						a.exportConnections()
					}
					view := "按域名分组"
					if a.ConnGroupByHost {
						view = "列表视图"
					}
					if m.Item(view).Chosen() {
						a.ConnGroupByHost = !a.ConnGroupByHost
					}
				})
			})
		})

		if a.ConnGroupByHost {
			a.connectionGroupsView(c, conns)
			return
		}

		ui.List(c, nil, len(conns), func(i int) {
			conn := conns[i]
			ui.Row(c).Gap(8).Padding(8, 12).Children(func() {
				text(c, conn.Host).Width(200)
				text(c, strings.ToUpper(conn.Network)).Width(50).TextColor(c.Theme().TextMuted)
				text(c, conn.Rule).Width(120).TextColor(c.Theme().TextMuted)
				text(c, strings.Join(conn.Chain, " → ")).Grow(1)
				text(c, humanBytes(conn.Download)+" ↓").Width(90)
				if ui.Button(c, a.trs("关闭")).Clicked() {
					go func() { _ = a.currentClient().CloseConnection(conn.ID) }()
				}
			})
		}).Grow(1).Background(c.Theme().Surface).Radius(8)
	})
}

// connectionGroupsView groups connections by host with aggregate traffic.
func (a *App) connectionGroupsView(c *ui.Context, conns []config.ConnectionView) {
	type group struct {
		host  string
		count int
		down  int64
		up    int64
	}
	byHost := map[string]*group{}
	for _, conn := range conns {
		g := byHost[conn.Host]
		if g == nil {
			g = &group{host: conn.Host}
			byHost[conn.Host] = g
		}
		g.count++
		g.down += conn.Download
		g.up += conn.Upload
	}
	var groups []*group
	for _, g := range byHost {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].down > groups[j].down })

	ui.List(c, nil, len(groups), func(i int) {
		g := groups[i]
		ui.Row(c).Gap(12).Padding(8, 12).Children(func() {
			text(c, g.host).Grow(1)
			ui.Badge(c, fmt.Sprintf("%d 连接", g.count))
			text(c, "↓"+humanBytes(g.down)+" ↑"+humanBytes(g.up)).Width(160).TextColor(c.Theme().TextMuted)
		})
	}).Grow(1).Background(c.Theme().Surface).Radius(8)
}
