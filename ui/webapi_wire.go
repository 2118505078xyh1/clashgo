package ui

import (
	"fmt"
	"time"

	"github.com/egoist/mygo"

	"clashgo/internal/webapi"
)

// startWebAPI starts the optional external HTTP/SSE API and wires command
// handling. The server is stopped automatically when the app quits.
func (a *App) startWebAPI() {
	if !a.Settings.WebAPIEnabled {
		return
	}
	secret := a.Settings.WebAPISecret
	if secret == "" {
		secret = a.Settings.Secret
	}
	srv := webapi.New(fmt.Sprintf("127.0.0.1:%d", a.Settings.WebAPIPort), secret)
	srv.SetCommandHandler(func(action, value string) error {
		if a.Settings.ReadOnly {
			return fmt.Errorf("read-only mode")
		}
		switch action {
		case "set-mode":
			a.setMode(value)
			return nil
		case "toggle-system-proxy":
			a.Settings.EnableSystemProxy = !a.Settings.EnableSystemProxy
			a.applySystemProxy()
			return nil
		case "reload-config":
			a.reapplyCore()
			return nil
		}
		return fmt.Errorf("unknown action: %s", action)
	})
	if err := srv.Start(); err != nil {
		a.Notices.Push("webapi::error", "Web API 启动失败: "+err.Error(), 2)
		return
	}
	a.WebAPIServer = srv
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) { srv.Close() })

	// Periodically publish a state snapshot + change events.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastConns := -1
		for range ticker.C {
			snap := webapi.Snapshot{
				Version: "clashgo/1.0", Mode: a.Settings.Mode,
				Up: a.Up, Down: a.Down, Connections: len(a.Connections),
				Proxies: map[string]any{}, Rules: nil, UpdatedAt: time.Now(),
			}
			srv.SetSnapshot(snap)
			if lastConns >= 0 && len(a.Connections) != lastConns {
				srv.Publish(webapi.Event{Type: "connections", Data: map[string]any{"count": len(a.Connections)}, Time: time.Now()})
			}
			lastConns = len(a.Connections)
		}
	}()
}
