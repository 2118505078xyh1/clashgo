// Package installer implements a self-contained Windows installer for
// clashgo. The main executable is embedded into the setup binary, so the
// user only needs one file (ClashGo-Setup.exe).
package installer

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// AppName is the display/install name.
const AppName = "ClashGo"

// Options controls what the installer does.
type Options struct {
	InstallDir        string
	DesktopShortcut   bool
	StartMenuShortcut bool
	AutoStart         bool
	LaunchAfter       bool
}

// ProgressFunc reports installation progress (0..100, message).
type ProgressFunc func(percent int, message string)

// setupFS is populated by the setup binary (see cmd/setup) via SetEmbeddedFS.
var setupFS embed.FS

// SetEmbeddedFS provides the embedded payload (clashgo.exe + resources).
func SetEmbeddedFS(f embed.FS) { setupFS = f }

// Run performs the installation.
func Run(opts Options, progress ProgressFunc) error {
	report := func(p int, m string) {
		if progress != nil {
			progress(p, m)
		}
	}
	if opts.InstallDir == "" {
		return fmt.Errorf("install directory is empty")
	}
	if err := os.MkdirAll(opts.InstallDir, 0o755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}
	dataDir := filepath.Join(opts.InstallDir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	// 覆盖安装：结束旧进程、清理旧程序文件，保留用户数据。
	report(5, "正在准备覆盖安装...")
	if err := prepareOverwrite(opts.InstallDir, dataDir); err != nil {
		return err
	}

	// Extract embedded payload (clashgo.exe, resources/*).
	report(10, "正在释放程序文件...")
	count := 0
	total := 0
	fs.WalkDir(setupFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			total++
		}
		return nil
	})
	var err error
	if total == 0 {
		// Fallback: look for a sibling clashgo.exe (dev builds).
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		src := filepath.Join(filepath.Dir(exe), "clashgo.exe")
		b, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("embedded payload missing and no sibling clashgo.exe: %w", err)
		}
		if err := os.WriteFile(filepath.Join(opts.InstallDir, "clashgo.exe"), b, 0o755); err != nil {
			return err
		}
		total = 1
	} else {
		err = fs.WalkDir(setupFS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			b, err := fs.ReadFile(setupFS, path)
			if err != nil {
				return err
			}
			// embed paths look like "payload/clashgo.exe" — strip the
			// leading payload/ so files land directly in InstallDir.
			rel := path
			if strings.HasPrefix(rel, "payload/") {
				rel = strings.TrimPrefix(rel, "payload/")
			}
			dst := filepath.Join(opts.InstallDir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, 0o755); err != nil {
				return err
			}
			count++
			report(10+count*50/total, "正在释放程序文件...")
			return nil
		})
		if err != nil {
			return err
		}
	}

	exePath := filepath.Join(opts.InstallDir, "clashgo.exe")
	icon := filepath.Join(opts.InstallDir, "app-icon.ico")
	if _, err := os.Stat(icon); err != nil {
		icon = exePath
	}
	report(65, "正在创建快捷方式...")
	if opts.DesktopShortcut {
		desktop, err := DesktopPath()
		if err == nil && desktop != "" {
			_ = CreateShortcut(ShortcutPath(desktop, AppName), exePath, "", opts.InstallDir, "ClashGo 代理客户端", icon)
		}
	}
	if opts.StartMenuShortcut {
		sm, err := StartMenuPath()
		if err == nil && sm != "" {
			dir := filepath.Join(sm, AppName)
			_ = os.MkdirAll(dir, 0o755)
			_ = CreateShortcut(ShortcutPath(dir, AppName), exePath, "", opts.InstallDir, "ClashGo 代理客户端", icon)
			_ = CreateShortcut(ShortcutPath(dir, "卸载 ClashGo"), exePath, "--uninstall", opts.InstallDir, "卸载 ClashGo", icon)
		}
	}

	report(80, "正在写入卸载信息...")
	_ = AddUninstallEntry(AppName, opts.InstallDir, exePath, "1.0.0")

	if opts.AutoStart {
		report(90, "正在设置开机自启...")
		_ = AddAutoStart(exePath)
	}
	report(100, "安装完成")
	return nil
}
