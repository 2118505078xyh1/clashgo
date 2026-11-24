package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
)

// mygo's ui.List is virtualized, so complex drag-and-drop is replaced with a
// lightweight alternative: pin (★/☆) and ↑/↓ buttons. All of this state is
// session-only, just like the existing sort/search state on App.
var (
	pinnedNodes     = map[string]bool{}
	nodeOrder       []string
	groupFold       = map[string]bool{} // folder key -> collapsed
	groupExpanded   = map[string]bool{} // proxy group -> expanded (default collapsed)
	regionGroupView bool
)

func (a *App) pageProxies(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(24).Gap(14).Children(func() {
		// Shared heading: only the overflow menu and the help button sit here.
		a.pageHeader(c, "代理组与节点", func() {
			ui.PopoverMenuButton(c, "⋮", func(m *ui.Menu) {
				if m.Item("定位当前节点").Chosen() {
					a.locateCurrent()
				}
				hide := "隐藏不可用节点"
				if a.HideUnavailable {
					hide = "显示不可用节点"
				}
				if m.Item(hide).Chosen() {
					a.HideUnavailable = !a.HideUnavailable
				}
				if m.Item("按地区建组").Chosen() {
					a.generateRegionGroups()
				}
				if m.Item("清除置顶").Chosen() {
					pinnedNodes = map[string]bool{}
				}
				regionLabel := "地区分组视图"
				if regionGroupView {
					regionLabel = "平铺节点视图"
				}
				if m.Item(regionLabel).Chosen() {
					regionGroupView = !regionGroupView
				}
				m.Separator()
				for i, label := range []string{"默认排序", "按名称", "按延迟"} {
					idx := i
					if m.Item(label).Radio(a.ProxySortMode == idx).Chosen() {
						a.ProxySortMode = idx
					}
				}
				if len(groupExpanded) > 0 && m.Item("全部折叠").Chosen() {
					groupExpanded = map[string]bool{}
				}
			})
		})

		// 工具栏：搜索与测速；模式切换在侧栏。
		card(c, func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
				ui.TextInput(c, &a.Search).Placeholder("搜索节点…").Width(220)
				if ui.PrimaryButton(c, a.tr("test_delay")).Clicked() {
					a.testAllDelays()
				}
				if len(a.busyNodes) > 0 && ui.Button(c, "取消测速").Clicked() {
					a.cancelDelayTest()
				}
			})
		})

		ui.Scroll(c).Grow(1).Gap(12).Children(func() {
			groups := a.sortedGroups()
			if len(groups) == 0 {
				card(c, func() {
					ui.Column(c).Gap(8).AlignItems(ui.Center).Padding(28, 0).Children(func() {
						ui.Icon(c, iconProxy).FontSize(48).TextColor(t.TextMuted)
						text(c, a.trs("暂无代理组")).FontSize(15).Bold()
						text(c, "请在「配置」页导入一个订阅，或在设置中检查内核状态。").
							FontSize(12).TextColor(t.TextMuted)
					})
				})
				return
			}
			for _, g := range groups {
				group := g
				card(c, func() {
					expanded := groupExpanded[group.Name]
					ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
						chev := iconChevronRight
						if expanded {
							chev = iconChevronDown
						}
						iconAction(c, chev, "展开/折叠", func() {
							groupExpanded[group.Name] = !expanded
						}, false)
						ui.Box(c).Size(28, 28).Radius(8).Center().Background(withAlpha(t.Accent, 0.14)).
							Children(func() { ui.Icon(c, iconProxy).FontSize(16).TextColor(t.Accent) })
						ui.Column(c).Gap(2).Children(func() {
							text(c, group.Name).Bold().FontSize(15)
							text(c, fmt.Sprintf("%d 个节点", len(group.All))).FontSize(11).TextColor(t.TextMuted)
						}).Grow(1)
						text(c, group.Now).TextColor(t.Accent).FontSize(13)
						busy := a.busyNodes["group:"+group.Name]
						if busy {
							iconAction(c, iconGauge, "测速中…", func() {}, true)
						} else {
							iconAction(c, iconGauge, "延迟测速", func() { a.testGroup(group.Name) }, false)
						}
						if a.NodeProbeBusy {
							iconAction(c, iconTarget, "探测中…", func() {}, true)
						} else {
							iconAction(c, iconTarget, "探测出口地区", func() { a.probeNodeIPs(group.Name, group.All, group.Now) }, false)
						}
						a.SpeedMu.Lock()
						speedBusy := a.SpeedTestBusy
						a.SpeedMu.Unlock()
						if speedBusy {
							iconAction(c, iconSpeed, "停止测速", a.cancelSpeedtest, false)
						} else {
							iconAction(c, iconSpeed, "完整测速", func() { a.runFullSpeedtest(group.Name, group.All, group.Now) }, false)
						}
					})
					if expanded {
						ui.Divider(c).Padding(6, 0)

						nodes := a.orderedNodes(group)
						renderNode := func(n string) {
							sel := n == group.Now
							proxy, _ := a.Proxies[n]
							row := ui.Row(c).Gap(10).Padding(7, 8)
							row.Children(func() {
								if sel {
									// Light fill plus 2px primary bars on both sides.
									ui.Box(c).Width(2).FillHeight().Background(t.Accent)
									ui.Icon(c, iconPlay).FontSize(12).TextColor(t.Accent)
								} else {
									text(c, "  ").FontSize(12)
								}
								// Name with feature chips.
								ui.Column(c).Gap(2).Children(func() {
									text(c, n).FontSize(13).Grow(1)
									if proxy.Type != "" {
										typeLabel := proxy.Type
										lower := strings.ToLower(proxy.Type)
										if lower == "hysteria2" || lower == "tuic" {
											typeLabel += " (实验性)"
										}
										text(c, typeLabel).FontSize(10).TextColor(t.TextMuted)
									}
								}).Grow(1)
								// Delay history bars.
								a.delayBars(c, n)
								if region := a.nodeRegionLabel(n); region != "" {
									ui.Badge(c, region).Width(44)
								}
								text(c, delayText(a.Delays[n])).FontSize(12).TextColor(a.delayColor(n)).Width(56)
								if sr, ok := a.SpeedResults[n]; ok && sr.DownloadKbps > 0 {
									text(c, "↓"+fmt.Sprintf("%.0fK", sr.DownloadKbps)).FontSize(11).
										TextColor(t.Success).Width(60)
								}
								// Lightweight stand-ins for drag-and-drop sorting.
								pin := "☆"
								if pinnedNodes[n] {
									pin = "★"
								}
								if ui.Button(c, pin).Width(26).FontSize(12).Clicked() {
									togglePinnedNode(n)
								}
								if !sel && ui.Button(c, a.tr("select")).Width(56).Clicked() {
									a.selectNode(group.Name, n)
								}
								if sel {
									ui.Box(c).Width(2).FillHeight().Background(t.Accent)
								}
							})
							if sel {
								row.Background(withAlpha(t.Accent, 0.13))
							}
						}

						shown := 0
						if regionGroupView {
							folders := a.nodeFoldersFrom(nodes)
							for _, f := range folders {
								shown += len(f.nodes)
							}
							for _, f := range folders {
								folder := f
								key := group.Name + "|" + folder.key
								collapsed := groupFold[key]
								ui.Row(c).Gap(8).AlignItems(ui.Center).Padding(4, 6).Children(func() {
									label := "▼"
									if collapsed {
										label = "▶"
									}
									if ui.Button(c, label+" "+folder.key).Clicked() {
										groupFold[key] = !collapsed
									}
									text(c, fmt.Sprintf("%d 个节点", len(folder.nodes))).
										FontSize(11).TextColor(t.TextMuted)
								})
								if !collapsed {
									for _, n := range folder.nodes {
										renderNode(n)
									}
								}
							}
						} else {
							for _, n := range nodes {
								if !a.nodeVisible(n) {
									continue
								}
								shown++
								renderNode(n)
							}
						}
						if shown == 0 {
							ui.Column(c).Gap(6).AlignItems(ui.Center).Padding(18, 0).Children(func() {
								ui.Icon(c, iconSearch).FontSize(36).TextColor(t.TextMuted)
								text(c, "没有匹配的节点").FontSize(12).TextColor(t.TextMuted)
							})
						}
					}
				})
			}
		})
	})
}

func (a *App) sortModeLabel() string {
	switch a.ProxySortMode {
	case 1:
		return "按名称"
	case 2:
		return "按延迟"
	default:
		return "默认排序"
	}
}

func (a *App) sortedNodes(g config.ProxyView) []string {
	nodes := append([]string(nil), g.All...)
	switch a.ProxySortMode {
	case 1: // name
		sort.Strings(nodes)
	case 2: // delay (unknown last)
		sort.SliceStable(nodes, func(i, j int) bool {
			di, dj := a.Delays[nodes[i]], a.Delays[nodes[j]]
			if di == 0 {
				di = 1 << 30
			}
			if dj == 0 {
				dj = 1 << 30
			}
			return di < dj
		})
	}
	return nodes
}

// orderedNodes layers pinning and manual ↑/↓ priority on top of the existing
// default/name/delay sorting. Pinned nodes always come first.
func (a *App) orderedNodes(g config.ProxyView) []string {
	nodes := a.sortedNodes(g)
	sort.SliceStable(nodes, func(i, j int) bool {
		pi, pj := pinnedNodes[nodes[i]], pinnedNodes[nodes[j]]
		if pi != pj {
			return pi
		}
		ri, rj := nodeRank(nodes[i]), nodeRank(nodes[j])
		if ri != rj {
			return ri < rj
		}
		return false
	})
	return nodes
}

func togglePinnedNode(node string) {
	pinnedNodes[node] = !pinnedNodes[node]
}

// nodeRank returns the manual priority of a node. Unranked nodes keep their
// sort-mode order and follow every explicitly moved node.
func nodeRank(node string) int {
	for i, n := range nodeOrder {
		if n == node {
			return i
		}
	}
	return len(nodeOrder)
}

// applyNodeOrder records a new manual order, retaining nodes from other
// groups that were moved earlier.
func applyNodeOrder(order []string) {
	seen := make(map[string]bool, len(order))
	next := make([]string, 0, len(nodeOrder)+len(order))
	for _, n := range order {
		next = append(next, n)
		seen[n] = true
	}
	for _, n := range nodeOrder {
		if !seen[n] {
			next = append(next, n)
		}
	}
	nodeOrder = next
}

// moveNode swaps a node with its displayed neighbour and records the result.
// Moves never cross the pinned/unpinned boundary.
func (a *App) moveNode(g config.ProxyView, node string, delta int) {
	nodes := a.orderedNodes(g)
	idx := -1
	for i, n := range nodes {
		if n == node {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	j := idx + delta
	if j < 0 || j >= len(nodes) {
		return
	}
	if pinnedNodes[nodes[j]] != pinnedNodes[node] {
		return
	}
	nodes[idx], nodes[j] = nodes[j], nodes[idx]
	applyNodeOrder(nodes)
}

type nodeFolder struct {
	key   string
	nodes []string
}

// nodeFoldersFrom groups visible nodes into collapsible region folders. It
// prefers the groups produced by "按地区建组", falling back to the probed
// region or the first character of the node name.
func (a *App) nodeFoldersFrom(nodes []string) []nodeFolder {
	byKey := map[string][]string{}
	for _, n := range nodes {
		if !a.nodeVisible(n) {
			continue
		}
		k := a.regionKeyFor(n)
		byKey[k] = append(byKey[k], n)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	folders := make([]nodeFolder, 0, len(keys))
	for _, k := range keys {
		folders = append(folders, nodeFolder{key: k, nodes: byKey[k]})
	}
	return folders
}

func (a *App) regionKeyFor(node string) string {
	for _, g := range a.AutoGroups {
		for _, m := range g.Members {
			if m == node {
				if g.Name != "" {
					return g.Name
				}
				return g.Code
			}
		}
	}
	if r := a.nodeRegionLabel(node); r != "" {
		return r
	}
	if node == "" {
		return "其它"
	}
	return string([]rune(node)[0])
}

func (a *App) nodeVisible(node string) bool {
	if a.HideUnavailable && a.Delays[node] < 0 {
		return false
	}
	if a.Search != "" && !containsFold(node, a.Search) {
		return false
	}
	return true
}

// delayBars draws up to 10 small colored bars from the delay history.
func (a *App) delayBars(c *ui.Context, node string) {
	p := a.Proxies[node]
	hist := p.History
	if len(hist) > 10 {
		hist = hist[len(hist)-10:]
	}
	ui.Row(c).Gap(2).Width(70).Children(func() {
		for _, h := range hist {
			col := c.Theme().Success
			switch {
			case h.Delay < 0:
				col = c.Theme().Danger
			case h.Delay >= 200:
				col = c.Theme().Warning
			}
			ui.Box(c).Size(5, 12).Radius(1).Background(withAlpha(col, 0.85))
		}
	})
}

func (a *App) locateCurrent() {
	// Jump to the first group whose current node matches search input, or
	// clear the search to reveal the current node.
	if a.Search != "" {
		a.Search = ""
	}
}

func (a *App) sortedGroups() []config.ProxyView {
	var groups []config.ProxyView
	for _, p := range a.Proxies {
		if p.Group {
			groups = append(groups, p)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups
}

func (a *App) delayColor(node string) ui.Color {
	d := a.Delays[node]
	switch {
	case d == 0:
		return cMuted(a)
	case d < 0:
		return cDanger(a)
	case d < 200:
		return cSuccess(a)
	default:
		return cWarning(a)
	}
}
