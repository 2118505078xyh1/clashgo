package profile

import (
	"log"
	"sync"
	"time"

	"clashgo/internal/config"
)

// ProfileTimer 按每个订阅的 update-interval 定时自动更新远程订阅。
//
// 对齐 Clash Verge Rev 的 core/timer.rs：
//   - 只调度 type=remote、allow-auto-update=true、update-interval>0 的订阅
//   - 首次触发时间 = updated + interval（已过期则立即触发）
//   - 每次更新后按完整周期重新排期
//   - 更新前后通过回调通知上层（ProfileUpdateStarted / Completed）
//
// 实现用每秒 tick + 下次更新时间表；订阅数量通常 < 100，足够且零依赖。
type ProfileTimer struct {
	mu       sync.Mutex
	mgr      *Manager
	next     map[string]time.Time // uid -> 下次更新时间
	stopCh   chan struct{}
	doneCh   chan struct{}
	running  bool
	onUpdate func(uid string, err error) // 更新完成回调（可空）
}

// NewTimer 创建定时器。onUpdate 在每次更新完成后被调用（err 为 nil 表示成功）。
func NewTimer(mgr *Manager, onUpdate func(uid string, err error)) *ProfileTimer {
	return &ProfileTimer{
		mgr:      mgr,
		next:     map[string]time.Time{},
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		onUpdate: onUpdate,
	}
}

// Start 启动定时循环，并按当前订阅重新排期。重复调用是幂等的。
func (t *ProfileTimer) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.mu.Unlock()

	// 重新创建 channel，支持 Stop 后再 Start。
	t.mu.Lock()
	t.stopCh = make(chan struct{})
	t.doneCh = make(chan struct{})
	stopCh, doneCh := t.stopCh, t.doneCh
	t.mu.Unlock()

	t.Refresh()
	go t.loop(stopCh, doneCh)
}

// Stop 停止定时循环。
func (t *ProfileTimer) Stop() {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	t.running = false
	close(t.stopCh)
	doneCh := t.doneCh
	t.mu.Unlock()
	<-doneCh
}

// Refresh 依据当前订阅列表重新计算排期。导入/删除/修改订阅后应调用。
func (t *ProfileTimer) Refresh() {
	t.mu.Lock()
	defer t.mu.Unlock()

	newNext := map[string]time.Time{}
	for _, item := range t.mgr.DB.Items {
		if sched, ok := nextUpdate(item); ok {
			newNext[item.UID] = sched
		}
	}
	t.next = newNext
}

// GetNextUpdateTime 返回某订阅的下次更新时间。ok=false 表示该订阅未启用自动更新。
func (t *ProfileTimer) GetNextUpdateTime(uid string) (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.next[uid]
	return at, ok
}

// nextUpdate 计算单个订阅的下次更新时间。
func nextUpdate(item *config.PrfItem) (time.Time, bool) {
	if item == nil || item.Type != config.ProfileRemote || item.Option == nil {
		return time.Time{}, false
	}
	if !item.Option.AllowAutoUpdate || item.Option.UpdateInterval <= 0 {
		return time.Time{}, false
	}
	interval := time.Duration(item.Option.UpdateInterval) * time.Minute
	base := time.Unix(item.Updated, 0)
	if base.IsZero() || item.Updated <= 0 {
		base = time.Now()
	}
	return base.Add(interval), true
}

func (t *ProfileTimer) loop(stopCh, doneCh chan struct{}) {
	defer close(doneCh)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case now := <-ticker.C:
			t.checkDue(now)
		}
	}
}

func (t *ProfileTimer) checkDue(now time.Time) {
	t.mu.Lock()
	var due []string
	for uid, at := range t.next {
		if !now.Before(at) {
			due = append(due, uid)
		}
	}
	t.mu.Unlock()

	for _, uid := range due {
		// 取出当前项排期信息（可能在更新期间被 Refresh 改动）
		t.mu.Lock()
		item := t.mgr.DB.Find(uid)
		_, ok := t.next[uid]
		t.mu.Unlock()
		if item == nil || !ok || item.Option == nil {
			continue
		}

		// 先重新排下一个周期，避免更新耗时导致重复触发。
		interval := time.Duration(item.Option.UpdateInterval) * time.Minute
		if interval <= 0 {
			interval = time.Hour
		}
		t.mu.Lock()
		t.next[uid] = now.Add(interval)
		t.mu.Unlock()

		err := t.mgr.Refresh(uid)
		if t.onUpdate != nil {
			t.onUpdate(uid, err)
		}
		if err != nil {
			log.Printf("profile timer: auto-update %s failed: %v", uid, err)
		}
	}
}
