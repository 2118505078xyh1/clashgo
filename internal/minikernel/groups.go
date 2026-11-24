package minikernel

import (
	"context"
	"net"
	"sync"
)

// ProxyGroup 是代理组接口：能列出成员、切换/测试节点。
type ProxyGroup interface {
	ProxyAdapter
	Members() []string
}

// Selectable 是可通过 API 手动选择节点的代理组。
type Selectable interface {
	Set(name string) bool
}

// Selector 是手动选择的代理组。
type Selector struct {
	name     string
	kernel   *Kernel
	members  []string
	selected string
	mu       sync.RWMutex
}

func NewSelector(k *Kernel, name string, members []string) *Selector {
	s := &Selector{name: name, kernel: k, members: members}
	if len(members) > 0 {
		s.selected = members[0]
	}
	return s
}

func (s *Selector) Name() string      { return s.name }
func (s *Selector) Members() []string { return append([]string(nil), s.members...) }
func (s *Selector) Selected() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selected
}

// Set 切换选中的节点，成功返回 true。
func (s *Selector) Set(name string) bool {
	for _, m := range s.members {
		if m == name {
			s.mu.Lock()
			s.selected = name
			s.mu.Unlock()
			return true
		}
	}
	return false
}

func (s *Selector) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	sel := s.Selected()
	if p, ok := s.kernel.Proxies[sel]; ok {
		return p.DialContext(ctx, m)
	}
	return nil, &DialError{"selector: no selected proxy"}
}

// URLTest 是自动测速选择延迟最低节点的代理组。
type URLTest struct {
	name    string
	kernel  *Kernel
	members []string
	delays  map[string]uint16 // 0 表示未测/失败
	forced  string            // 用户手动指定的节点（优先于测速结果）
	mu      sync.RWMutex
}

func NewURLTest(k *Kernel, name string, members []string) *URLTest {
	return &URLTest{name: name, kernel: k, members: members, delays: map[string]uint16{}}
}

func (t *URLTest) Name() string      { return t.name }
func (t *URLTest) Members() []string { return append([]string(nil), t.members...) }

func (t *URLTest) Delays() map[string]uint16 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]uint16, len(t.delays))
	for k, v := range t.delays {
		out[k] = v
	}
	return out
}

// SetDelay 记录一次延迟测试结果（0 表示失败）。
func (t *URLTest) SetDelay(name string, ms uint16) {
	t.mu.Lock()
	t.delays[name] = ms
	t.mu.Unlock()
}

// best 返回延迟最低且测试成功的节点。
func (t *URLTest) best() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.forced != "" {
		return t.forced
	}
	var best string
	var bestMS uint16
	for _, m := range t.members {
		d := t.delays[m]
		if d > 0 && (best == "" || d < bestMS) {
			best, bestMS = m, d
		}
	}
	if best != "" {
		return best
	}
	// 全部未测：回退第一个成员。
	if len(t.members) > 0 {
		return t.members[0]
	}
	return ""
}

// Set 手动指定节点（覆盖测速结果），兼容 Clash API 的 PUT /proxies/{group}。
func (t *URLTest) Set(name string) bool {
	for _, m := range t.members {
		if m == name {
			t.mu.Lock()
			t.forced = name
			t.mu.Unlock()
			return true
		}
	}
	return false
}

func (t *URLTest) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	name := t.best()
	if p, ok := t.kernel.Proxies[name]; ok {
		return p.DialContext(ctx, m)
	}
	return nil, &DialError{"url-test: no member"}
}

// Fallback 是主备故障转移组：按配置顺序返回第一个可用节点。
type Fallback struct {
	name    string
	kernel  *Kernel
	members []string
	delays  map[string]uint16 // >0 表示可用
	mu      sync.RWMutex
}

func NewFallback(k *Kernel, name string, members []string) *Fallback {
	return &Fallback{name: name, kernel: k, members: members, delays: map[string]uint16{}}
}

func (f *Fallback) Name() string      { return f.name }
func (f *Fallback) Members() []string { return append([]string(nil), f.members...) }

func (f *Fallback) SetDelay(name string, ms uint16) {
	f.mu.Lock()
	f.delays[name] = ms
	f.mu.Unlock()
}

func (f *Fallback) Delays() map[string]uint16 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]uint16, len(f.delays))
	for k, v := range f.delays {
		out[k] = v
	}
	return out
}

func (f *Fallback) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	f.mu.RLock()
	var chosen string
	for _, name := range f.members {
		if f.delays[name] > 0 {
			chosen = name
			break
		}
	}
	if chosen == "" && len(f.members) > 0 {
		chosen = f.members[0] // 全部未测时回退第一个
	}
	f.mu.RUnlock()
	if p, ok := f.kernel.Proxies[chosen]; ok {
		return p.DialContext(ctx, m)
	}
	return nil, &DialError{"fallback: no member"}
}

// LoadBalance 是负载均衡组：按原子计数轮询成员。
type LoadBalance struct {
	name    string
	kernel  *Kernel
	members []string
	counter uint64
	mu      sync.Mutex
}

func NewLoadBalance(k *Kernel, name string, members []string) *LoadBalance {
	return &LoadBalance{name: name, kernel: k, members: members}
}

func (l *LoadBalance) Name() string      { return l.name }
func (l *LoadBalance) Members() []string { return append([]string(nil), l.members...) }

func (l *LoadBalance) DialContext(ctx context.Context, m *Metadata) (net.Conn, error) {
	l.mu.Lock()
	l.counter++
	idx := int(l.counter % uint64(len(l.members)))
	l.mu.Unlock()
	name := l.members[idx]
	if p, ok := l.kernel.Proxies[name]; ok {
		return p.DialContext(ctx, m)
	}
	return nil, &DialError{"load-balance: no member"}
}
