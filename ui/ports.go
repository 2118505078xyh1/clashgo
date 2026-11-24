package ui

import (
	"fmt"

	"github.com/egoist/mygo"

	"clashgo/internal/listener"
)

func (a *App) applyPorts() {
	ports := map[string]int{
		"mixed": a.parseIntOr(a.portText, a.Settings.MixedPort),
		"socks": a.parseIntOr(a.socksPortText, a.Settings.SocksPort),
		"http":  a.parseIntOr(a.httpPortText, a.Settings.HTTPPort),
	}
	if conflicts := listener.CheckSet(ports, "tcp"); len(conflicts) > 0 {
		a.notify("端口冲突", conflicts[0].Reason+"\n请关闭占用该端口的程序后重试")
		return
	}
	a.Settings.MixedPort = ports["mixed"]
	a.Settings.SocksPort = ports["socks"]
	a.Settings.HTTPPort = ports["http"]
	a.mustSaveSettings()
	a.applySystemProxy()
	a.reapplyCore()
	a.notify("端口设置", "已保存并重启内核")
}

func (a *App) checkPorts() {
	ports := map[string]int{
		"mixed": a.parseIntOr(a.portText, 0),
		"socks": a.parseIntOr(a.socksPortText, 0),
		"http":  a.parseIntOr(a.httpPortText, 0),
	}
	conflicts := listener.CheckSet(ports, "tcp")
	if len(conflicts) == 0 {
		a.notify("端口检查", "所有端口均可用")
		return
	}
	msg := ""
	for _, c := range conflicts {
		msg += c.Reason + "\n"
	}
	a.notify("端口被占用", msg)
	_ = mygo.App
}

func (a *App) parseIntOr(s string, fallback int) int {
	var v int
	if _, err := fmt.Sscan(s, &v); err != nil || v < 1 || v > 65535 {
		return fallback
	}
	return v
}
