//go:build windows

package installer

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// prepareOverwrite handles installing over an existing installation:
// stops the running old instance and removes old program files, while
// preserving the user's data directory (settings, profiles, logs).
func prepareOverwrite(installDir string, dataDir string) error {
	exe := filepath.Join(installDir, "clashgo.exe")
	// 结束正在运行的旧实例，避免文件被占用导致覆盖失败。
	stopRunningInstances(filepath.Base(exe))
	time.Sleep(300 * time.Millisecond)

	// 删除旧的程序文件（保留 data 目录里的用户配置）。
	entries, _ := os.ReadDir(installDir)
	for _, e := range entries {
		if e.IsDir() {
			if e.Name() == "data" {
				continue // 保留用户数据
			}
			_ = os.RemoveAll(filepath.Join(installDir, e.Name()))
			continue
		}
		_ = os.Remove(filepath.Join(installDir, e.Name()))
	}
	return nil
}

// stopRunningInstances terminates processes with the given executable name.
func stopRunningInstances(name string) {
	if name == "" {
		return
	}
	// taskkill /F /IM <name> /T
	cmd := exec.Command("taskkill", "/F", "/IM", name, "/T")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}
