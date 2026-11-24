// Command clashgo is a pure-Go Clash client: 自研内核 kernel in-process,
// MyGo native UI. No JavaScript, no bundled browser, no external sidecar.
package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"clashgo/internal/bootguard"
	"clashgo/internal/installer"
	"clashgo/internal/paths"
	"clashgo/internal/safemode"
	"clashgo/internal/service"
	"clashgo/internal/singleinstance"
	"clashgo/internal/sysproxy"
	"clashgo/internal/wingeo"
	cgui "clashgo/ui"
)

const appName = "clashgo"
const clearProxyOnExit = true

func main() {
	// Uninstall is invoked by the Start Menu shortcut and by Add/Remove
	// Programs, both of which run clashgo.exe with this flag. Handle it
	// before any app data is created or a second instance is locked.
	if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
		installer.Uninstall()
		return
	}
	if err := paths.Init(appName); err != nil {
		log.Fatalf("init paths: %v", err)
	}
	// Windows service mode: run the privileged core host without UI.
	if len(os.Args) > 1 && os.Args[1] == "--service" {
		if err := service.RunService(); err != nil {
			log.Fatalf("service: %v", err)
		}
		return
	}
	// Double-clicking the exe while ClashGo is already hidden in the tray
	// should bring the window back, not show an error and exit.
	var (
		app         *cgui.App
		winMu       sync.Mutex
		win         *mygo.Window
		showPending bool
	)
	showWindow := func() {
		winMu.Lock()
		ap, w := app, win
		if w == nil {
			showPending = true
			winMu.Unlock()
			return
		}
		winMu.Unlock()
		if ap != nil {
			ap.SetHidden(false)
		}
		w.Show()
		w.Focus()
	}
	release, err := singleinstance.Try(19097, showWindow)
	if errors.Is(err, singleinstance.ErrAlreadyRunning) {
		return // the running instance has been asked to show its window
	}
	if err != nil {
		log.Fatalf("single instance: %v", err)
	}
	defer release()

	// Expose paths to the UI layer via injected globals.
	cgui.ConfigFile = paths.Settings
	cgui.RuntimeFile = paths.Runtime

	mygo.App.SetName("ClashGo")
	mygo.App.SetVersion(appVersion)

	// Boot guard: detect repeated failed startups and fall back to defaults.
	bg := bootguard.New(paths.Home)
	bootState := bg.MarkStarting()
	if bootState.FailStreak >= 3 {
		log.Printf("detected %d consecutive failed starts; falling back to default profile", bootState.FailStreak)
		cgui.ResetToDefaultProfile()
	}

	a, err := cgui.NewApp()
	if err != nil {
		log.Fatalf("init app: %v", err)
	}
	winMu.Lock()
	app = a
	winMu.Unlock()
	mygo.App.OnOpenURL(a.HandleOpenURL)
	// Non-interactive / unattended mode: skip any first-run prompt.
	if safemode.NonInteractive() {
		log.Printf("non-interactive mode enabled (CLASHGO_NONINTERACTIVE/CI)")
	}
	// Restore window geometry from last session.
	winGeoPath := filepath.Join(paths.Home, "window.json")
	geo, hasGeo := wingeo.Load(winGeoPath)
	// 用实际屏幕尺寸约束窗口，避免恢复到屏幕外导致"启动后看不到窗口"。
	sw, sh := screenSize()
	geo = wingeo.Clamp(geo, 820, 600, sw, sh)
	if !hasGeo || geo.X < 0 || geo.Y < 0 {
		geo = wingeo.Geometry{X: 80, Y: 60, Width: 1000, Height: 700}
	}
	// 清理逻辑：退出时清除系统代理，避免残留导致断网。
	// 只在系统代理仍然指向本程序的混合端口时才清理，
	// 避免把用户自己设置的其他代理一起关掉。
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		bg.MarkClosed()
		if clearProxyOnExit && a.Settings.EnableSystemProxy {
			port := a.Settings.MixedPort
			if a.EffectivePort > 0 {
				port = a.EffectivePort
			}
			if _, err := sysproxy.ClearIfPointsTo(port); err != nil {
				log.Printf("clear system proxy on exit: %v", err)
			}
		}
		if a.Guard != nil {
			a.Guard.Stop()
		}
	})

	trayIcon := loadTrayIcon()
	var tray *mygo.Tray
	var trayMenu *mygo.Tray

	mygo.App.WhenReady(func() {
		// Plain go build embeds no Windows icon resource; set the window/
		// taskbar icon explicitly so it is the same ClashGo mark as the tray.
		if err := mygo.App.Dock.SetIcon(loadAppIcon()); err != nil {
			log.Printf("app icon: %v", err)
		}
		bg.MarkRunning()
		w := mygo.NewWindow(mygo.WindowOptions{
			Title:     "ClashGo v" + appVersion,
			X:         geo.X,
			Y:         geo.Y,
			Width:     geo.Width,
			Height:    geo.Height,
			MinWidth:  820,
			MinHeight: 600,
			Content:   ui.View(a.View),
		})
		winMu.Lock()
		win = w
		pending := showPending
		showPending = false
		winMu.Unlock()
		a.SetWindow(w)

		saveGeometry := func() {
			x, y := w.Position()
			ww, hh := w.Size()
			_ = wingeo.Save(winGeoPath, wingeo.Geometry{
				X: x, Y: y, Width: ww, Height: hh, Maximized: w.IsMaximized(),
			})
		}
		// 启动时和第二次双击 exe 时都要把窗口放到前台。
		w.Show()
		w.Focus()
		if pending {
			showWindow()
		}

		// 右上角 X 正常关闭窗口；Hide 到托盘只由"最小化到托盘"按钮完成。
		w.OnClose(func(e *mygo.CloseEvent) { saveGeometry() })
		w.OnShow(func() { a.SetHidden(false) })
		w.OnHide(func() {
			a.SetHidden(true)
			saveGeometry()
		})

		if len(trayIcon) > 0 {
			// 托盘使用彩色图标，直接显示蓝紫渐变标识。
			tray, err = mygo.NewTray(mygo.TrayOptions{
				Icon:    trayIcon,
				ToolTip: "ClashGo",
				Menu:    a.BuildTrayMenu(w),
			})
			if err != nil {
				log.Printf("托盘: %v", err)
			} else {
				tray.OnClick(showWindow)
			}
			trayMenu = tray
			a.Tray = tray
			_ = tray.SetIcon(loadTrayIcon(), false)
			go a.RefreshTrayMenu()
		}

		a.RegisterHotkeys(w)
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
	_ = trayMenu
}

func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}
