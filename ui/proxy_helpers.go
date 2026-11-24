package ui

import (
	"context"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/controller"
)

func containsFold(s, sub string) bool { return len(sub) == 0 || containsLower(s, sub) }

func containsLower(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func cMuted(a *App) ui.Color   { return themeColor("muted") }
func cDanger(a *App) ui.Color  { return themeColor("danger") }
func cSuccess(a *App) ui.Color { return themeColor("success") }
func cWarning(a *App) ui.Color { return themeColor("warning") }

func themeColor(which string) ui.Color {
	switch which {
	case "danger":
		return ui.Hex("#f85149")
	case "success":
		return ui.Hex("#3fb950")
	case "warning":
		return ui.Hex("#d29922")
	default:
		return ui.Hex("#8b949e")
	}
}

func (a *App) selectNode(group, node string) {
	go func() {
		if err := a.currentClient().SelectNode(group, node); err != nil {
			logf("select node: %v", err)
			return
		}
		if item := a.Profiles.DB.CurrentItem(); item != nil {
			_ = a.Profiles.RecordSelection(item.UID, group, node)
		}
	}()
	if p, ok := a.Proxies[group]; ok {
		p.Now = node
		a.Proxies[group] = p
	}
}

func (a *App) cancelDelayTest() {
	a.delayMu.Lock()
	cancel := a.delayCancel
	a.delayCancel = nil
	a.delayGen++
	a.delayMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// 清空全部测速标记，避免取消后按钮一直停在“测速中”。
	for k := range a.busyNodes {
		delete(a.busyNodes, k)
	}
}

func (a *App) testGroup(group string) {
	if _, ok := a.Proxies[group]; !ok {
		return
	}
	a.startDelayTest([]string{group})
}

func (a *App) testAllDelays() {
	// 用户主动测速算活动，确保内核未被轻量模式挂起。
	if a.Lightweight != nil {
		a.Lightweight.Activity()
	}
	var groups []string
	for name, p := range a.Proxies {
		if p.Group {
			groups = append(groups, name)
		}
	}
	if len(groups) == 0 {
		a.notify("提示", "暂无可测速的代理组")
		return
	}
	// 所有代理组共用一个 context，取消一次就能停掉整批测速。
	a.startDelayTest(groups)
}

// startDelayTest 并发测速一批代理组，并在 UI 线程统一写回结果。
// updateHealthFromDelays 用已有的测速结果更新节点健康状态（不额外发起网络请求）。
// 只有在确实测过、且全部节点都失败时才判定为“全挂”。
func (a *App) updateHealthFromDelays(delays map[string]int) {
	if len(delays) == 0 {
		return
	}
	alive := 0
	for _, v := range delays {
		if v > 0 {
			alive++
		}
	}
	a.NodesAllDown = alive == 0
	a.LastHealthAt = time.Now()
}

// checkNodesHealth 对所有代理组做一次测速体检。
// 返回 true 表示至少有一个节点可用。
func (a *App) checkNodesHealth() bool {
	groups := a.groupNames()
	if len(groups) == 0 {
		a.NodesAllDown = false
		a.LastHealthAt = time.Now()
		return true
	}
	opts := controller.DelayOptions{
		URL: a.Settings.LatencyTestURL, Timeout: a.Settings.LatencyTimeout,
		Retries: 1, Concurrency: 4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	alive := 0
	for _, g := range groups {
		batch := a.currentClient().TestNodes(ctx, a.Proxies[g].All, opts)
		for _, r := range batch {
			if r.Delay > 0 {
				alive++
			}
		}
	}
	a.NodesAllDown = alive == 0
	a.LastHealthAt = time.Now()
	return !a.NodesAllDown
}

func (a *App) startDelayTest(groups []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	a.delayMu.Lock()
	if a.delayCancel != nil {
		a.delayCancel()
	}
	a.delayGen++
	gen := a.delayGen
	a.delayCancel = cancel
	a.delayMu.Unlock()

	type task struct {
		group string
		nodes []string
	}
	var tasks []task
	for _, g := range groups {
		p, ok := a.Proxies[g]
		if !ok {
			continue
		}
		nodes := append([]string(nil), p.All...)
		tasks = append(tasks, task{group: g, nodes: nodes})
		a.busyNodes["group:"+g] = true
		for _, n := range nodes {
			a.busyNodes[n] = true
		}
	}
	if len(tasks) == 0 {
		cancel()
		a.delayMu.Lock()
		if a.delayGen == gen {
			a.delayCancel = nil
		}
		a.delayMu.Unlock()
		return
	}

	opts := controller.DelayOptions{
		URL: a.Settings.LatencyTestURL, Timeout: a.Settings.LatencyTimeout,
		Retries: 2, Concurrency: 4,
	}
	var mu sync.Mutex
	results := map[string]int{}
	var wg sync.WaitGroup
	go func() {
		defer cancel()
		for _, t := range tasks {
			wg.Add(1)
			go func(t task) {
				defer wg.Done()
				batch := a.currentClient().TestNodes(ctx, t.nodes, opts)
				mu.Lock()
				for _, r := range batch {
					results[r.Name] = r.Delay
				}
				mu.Unlock()
			}(t)
		}
		wg.Wait()
		a.win.Update(func() {
			a.delayMu.Lock()
			if a.delayGen == gen {
				a.delayCancel = nil
			}
			a.delayMu.Unlock()
			for _, t := range tasks {
				delete(a.busyNodes, "group:"+t.group)
				for _, n := range t.nodes {
					delete(a.busyNodes, n)
				}
			}
			if ctx.Err() != nil {
				return // 已取消：保留上一次的延迟值
			}
			for name, delay := range results {
				a.Delays[name] = delay
			}
			// 测速结果同时用于节点健康告警（仅提示，不自动关闭系统代理）。
			a.updateHealthFromDelays(results)
			// 刷新后自动按延迟从小到大排序（延迟越小越好），
			// 这样就不需要手动 ↑/↓ 排序按钮了。
			a.ProxySortMode = 2
		})
	}()
}
