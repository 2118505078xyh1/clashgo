// Command setup is the ClashGo installer. It embeds clashgo.exe and shows a
// native install wizard (location, shortcuts, autostart).
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"clashgo/internal/hidewin"
	"clashgo/internal/installer"
)

//go:embed payload/*
var payload embed.FS

type setupState struct {
	win          *mygo.Window
	installDir   string
	desktop      bool
	startMenu    bool
	autoStart    bool
	launchAfter  bool
	busy         bool
	progress     int
	progressText string
	done         bool
	errText      string
	mu           sync.Mutex
}

func main() {
	// Handle --uninstall quietly (invoked from Start Menu / Add-Remove).
	uninstall := flag.Bool("uninstall", false, "uninstall ClashGo")
	flag.Parse()
	if *uninstall {
		runUninstall()
		return
	}

	installer.SetEmbeddedFS(payload)
	s := &setupState{desktop: true, startMenu: true, autoStart: false, launchAfter: true}
	defaultDir := filepath.Join(userLocalAppData(), AppDirName)
	if runtime.GOOS != "windows" {
		defaultDir = filepath.Join(userHome(), ".clashgo")
	}
	s.installDir = defaultDir

	mygo.App.SetName("ClashGo Setup")
	mygo.App.SetVersion("1.0.0")
	mygo.App.WhenReady(func() {
		s.win = mygo.NewWindow(mygo.WindowOptions{
			Title:     "ClashGo 安装程序",
			Width:     640,
			Height:    560,
			MinWidth:  600,
			MinHeight: 520,
			Content:   ui.View(s.view),
		})
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

func (s *setupState) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(28).Gap(16).Children(func() {
		ui.Text(c, "ClashGo 安装程序").FontSize(24).Bold()
		ui.Text(c, "纯 Go 桌面代理客户端 · 单文件安装").FontSize(12).TextColor(t.TextMuted)

		if s.done {
			s.viewDone(c)
			return
		}
		if s.busy {
			s.viewProgress(c)
			return
		}

		// Install location.
		ui.Text(c, "安装位置").FontSize(14).Bold()
		ui.Row(c).Gap(8).Children(func() {
			ui.TextInput(c, &s.installDir).Grow(1)
			if ui.Button(c, "浏览...").Clicked() {
				s.browseInstallDir()
			}
		})

		ui.Divider(c).Padding(4, 0)
		ui.Text(c, "安装选项").FontSize(14).Bold()
		ui.Checkbox(c, &s.desktop, "创建桌面快捷方式")
		ui.Checkbox(c, &s.startMenu, "创建开始菜单快捷方式")
		ui.Checkbox(c, &s.autoStart, "开机时自动启动 ClashGo")
		ui.Checkbox(c, &s.launchAfter, "安装完成后启动 ClashGo")

		if s.errText != "" {
			ui.Text(c, s.errText).TextColor(t.Danger).FontSize(12)
		}
		ui.Spacer(c).Grow(1)
		ui.Row(c).Gap(10).Justify(ui.End).Children(func() {
			if ui.Button(c, "取消").Clicked() {
				mygo.App.Quit()
			}
			if ui.PrimaryButton(c, "安装").Clicked() {
				s.startInstall()
			}
		})
	})
}

func (s *setupState) viewProgress(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Gap(16).Children(func() {
		ui.Text(c, "正在安装...").FontSize(20).Bold()
		ui.Text(c, s.progressText).FontSize(13).TextColor(t.TextMuted)
		ui.Progress(c, float64(s.progress)/100).Height(8)
		ui.Text(c, fmt.Sprintf("%d%%", s.progress)).FontSize(12)
	})
}

func (s *setupState) viewDone(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Gap(16).Children(func() {
		ui.Text(c, "✓ 安装完成").FontSize(22).Bold().TextColor(t.Success)
		ui.Text(c, "ClashGo 已安装到：").FontSize(13)
		ui.Text(c, s.installDir).FontSize(12).TextColor(t.TextMuted)
		if s.errText != "" {
			ui.Text(c, "注意："+s.errText).FontSize(12).TextColor(t.Warning)
		}
		ui.Spacer(c).Grow(1)
		ui.Row(c).Justify(ui.End).Children(func() {
			if ui.PrimaryButton(c, "完成").Clicked() {
				mygo.App.Quit()
			}
		})
	})
}

func (s *setupState) browseInstallDir() {
	paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
		Title:       "选择安装位置",
		Directory:   true,
		DefaultPath: s.installDir,
	})
	if err == nil && len(paths) > 0 {
		s.installDir = paths[0]
	}
}

func (s *setupState) startInstall() {
	s.mu.Lock()
	s.busy = true
	s.progress = 0
	s.progressText = "准备中..."
	s.mu.Unlock()
	go func() {
		err := installer.Run(installer.Options{
			InstallDir:        s.installDir,
			DesktopShortcut:   s.desktop,
			StartMenuShortcut: s.startMenu,
			AutoStart:         s.autoStart,
		}, func(p int, m string) {
			s.mu.Lock()
			s.progress, s.progressText = p, m
			s.mu.Unlock()
			s.win.Invalidate()
		})
		s.mu.Lock()
		s.busy = false
		if err != nil {
			s.errText = err.Error()
		} else {
			s.done = true
		}
		s.mu.Unlock()
		s.win.Update(func() {})
		if err == nil && s.launchAfter {
			exe := filepath.Join(s.installDir, "clashgo.exe")
			cmd := hidewin.Command(exe)
			cmd.Start()
		}
	}()
}

func runUninstall() {
	// The shared routine reads the registry InstallLocation and also clears
	// the default location, so a stale entry from an older build is handled.
	fmt.Println("卸载目录:", installer.InstalledLocation())
	installer.Uninstall()
	fmt.Println("ClashGo 已卸载")
}

// AppDirName is the default install directory name.
const AppDirName = "ClashGo"

func userLocalAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	return filepath.Join(userHome(), "AppData", "Local")
}

func userHome() string {
	h, _ := os.UserHomeDir()
	if h == "" {
		h = "."
	}
	return h
}
