package ui

import (
	"testing"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/config"
)

// TestProxyStatusCardClick 验证首页大状态卡可以被点击切换系统代理开关。
//
// 这是真实踩过的坑：卡片用 Row + Cursor + Clicked() 构造，
// 但 Clicked() 依赖 flagClickable，而该标志只有 OnClick 才会设置。
func TestProxyStatusCardClick(t *testing.T) {
	a := &App{
		Settings:  config.DefaultSettings(),
		Proxies:   map[string]config.ProxyView{},
		Delays:    map[string]int{},
		busyNodes: map[string]bool{},
	}
	// 用假的系统代理写入，避免测试真的改注册表。
	origSet := sysproxySetHook
	sysproxySetHook = func(enable bool, server, bypass string) error {
		a.Settings.EnableSystemProxy = enable
		return nil
	}
	defer func() { sysproxySetHook = origSet }()

	view := func(c *ui.Context) { a.proxyStatusCard(c) }
	tt := ui.NewTester(view, 700, 300)
	tt.Frame()

	before := a.Settings.EnableSystemProxy
	if err := tt.Click("代理未开启"); err != nil {
		t.Fatalf("click failed: %v", err)
	}
	tt.Frame()

	if a.Settings.EnableSystemProxy == before {
		t.Fatalf("点击后系统代理开关没有变化 (before=%v)", before)
	}
}

// TestProxyStatusCardRepaints 验证点击后下一帧显示新状态。
func TestProxyStatusCardRepaints(t *testing.T) {
	a := &App{
		Settings:  config.DefaultSettings(),
		Proxies:   map[string]config.ProxyView{},
		Delays:    map[string]int{},
		busyNodes: map[string]bool{},
	}
	origSet := sysproxySetHook
	sysproxySetHook = func(enable bool, server, bypass string) error {
		a.Settings.EnableSystemProxy = enable
		return nil
	}
	defer func() { sysproxySetHook = origSet }()

	var shown string
	view := func(c *ui.Context) {
		a.proxyStatusCard(c)
		if a.Settings.EnableSystemProxy {
			shown = "on"
		} else {
			shown = "off"
		}
	}
	tt := ui.NewTester(view, 700, 300)
	tt.Frame()
	if shown != "off" {
		t.Fatalf("初始应为 off, got %s", shown)
	}
	if err := tt.Click("代理未开启"); err != nil {
		t.Fatalf("click: %v", err)
	}
	tt.Frame()
	if shown != "on" {
		t.Fatalf("点击后应显示 on, got %s", shown)
	}
}
