package ui

import (
	"fmt"

	"clashgo/internal/guard"
	"clashgo/internal/sysproxy"
)

// refreshGuard starts or stops the system-proxy guard based on settings.
func (a *App) refreshGuard() {
	if a.Guard != nil {
		a.Guard.Stop()
		a.Guard = nil
	}
	if !a.Settings.EnableSystemProxy || !a.Settings.EnableProxyGuard {
		return
	}
	server := fmt.Sprintf("127.0.0.1:%d", a.Settings.MixedPort)
	if a.effectivePort > 0 {
		server = fmt.Sprintf("127.0.0.1:%d", a.effectivePort)
	}
	applier := guard.ApplierFunc{
		GetFn: func() (bool, string, string, error) {
			st, err := sysproxy.GetStatus()
			if err != nil {
				return false, "", "", err
			}
			return st.Enable, st.Server, st.Bypass, nil
		},
		SetFn: func(enable bool, srv, bypass string) error {
			return sysproxy.Apply(enable, srv, bypass)
		},
	}
	a.Guard = guard.New(applier, server, a.Settings.ProxyBypass, 30, func(reason string) {
		if a.win == nil {
			return
		}
		a.win.Update(func() {
			a.notify("代理守卫", reason)
			a.Settings.EnableProxyGuard = false
			a.mustSaveSettings()
		})
	})
	a.Guard.Start()
}
