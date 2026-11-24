package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"clashgo/internal/config"
)

func (a *App) toggleSystemProxyFromTray() {
	a.Settings.EnableSystemProxy = !a.Settings.EnableSystemProxy
	a.applySystemProxy()
}

// buildTrayMenu builds the tray menu, including proxy groups as checkbox
// submenus so users can switch nodes without opening the window.
func (a *App) BuildTrayMenu(win *mygo.Window) *mygo.Menu {
	items := []*mygo.MenuItem{
		{Label: "显示窗口", Click: func(*mygo.MenuItem, *mygo.Window) { win.Show() }},
		{Label: "系统代理: " + map[bool]string{true: "开", false: "关"}[a.Settings.EnableSystemProxy],
			Type: mygo.MenuItemCheckbox, Checked: a.Settings.EnableSystemProxy,
			Click: func(*mygo.MenuItem, *mygo.Window) { a.toggleSystemProxyFromTray() }},
		{Label: "TUN 模式", Type: mygo.MenuItemCheckbox, Checked: a.Settings.EnableTUN,
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.Settings.EnableTUN = !a.Settings.EnableTUN
				a.mustSaveSettings()
				a.reapplyCore()
			}},
		{Label: "复制代理环境变量", Click: func(*mygo.MenuItem, *mygo.Window) {
			port := a.Settings.MixedPort
			mygo.Clipboard.WriteText(fmt.Sprintf("export http_proxy=http://127.0.0.1:%d\nexport https_proxy=http://127.0.0.1:%d\nexport all_proxy=socks5://127.0.0.1:%d", port, port, port))
		}},
		mygo.Separator(),
	}
	// Mode submenu.
	var modeSub []*mygo.MenuItem
	for _, m := range []struct{ key, label string }{{"rule", "规则（推荐）"}, {"global", "全局（排错用）"}} {
		mk := m.key
		modeSub = append(modeSub, &mygo.MenuItem{
			Label: m.label, Type: mygo.MenuItemRadio, Checked: a.Settings.Mode == mk,
			Click: func(*mygo.MenuItem, *mygo.Window) { a.setMode(mk) },
		})
	}
	items = append(items, &mygo.MenuItem{Label: "代理模式", Submenu: modeSub}, mygo.Separator())

	groups := a.sortedGroups()
	for _, g := range groups {
		// GLOBAL 组与"代理模式"重复，不在节点列表里展示。
		if strings.EqualFold(g.Name, "GLOBAL") {
			continue
		}
		g := g
		var sub []*mygo.MenuItem
		nodes := append([]string(nil), g.All...)
		sort.Strings(nodes)
		for _, node := range nodes {
			// DIRECT / REJECT 等已在"代理模式"中体现，避免重复。
			if isSpecialNode(node) {
				continue
			}
			n := node
			sub = append(sub, &mygo.MenuItem{
				Label:   n,
				Type:    mygo.MenuItemCheckbox,
				Checked: n == g.Now,
				Click:   func(*mygo.MenuItem, *mygo.Window) { a.selectNode(g.Name, n) },
			})
		}
		if len(sub) == 0 {
			continue
		}
		items = append(items, &mygo.MenuItem{Label: g.Name, Submenu: sub})
	}
	items = append(items, mygo.Separator(), &mygo.MenuItem{
		Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() },
	})
	return mygo.NewMenu(items)
}

// refreshTrayMenu periodically rebuilds the tray menu so node selections and
// newly loaded subscriptions show up.
func (a *App) RefreshTrayMenu() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if a.Tray == nil || a.win == nil {
			continue
		}
		// Build off the UI thread; snapshot under win.Update to avoid races
		// with pollLoop mutating a.Proxies.
		done := make(chan *mygo.Menu, 1)
		a.win.Update(func() { done <- a.BuildTrayMenu(a.win) })
		menu := <-done
		a.win.Invalidate()
		a.Tray.SetMenu(menu)
	}
}

var _ = config.ProxyView{}
