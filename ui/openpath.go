package ui

import (
	"os/exec"
	"runtime"

	"clashgo/internal/hidewin"
)

// openPath 用系统默认的文件管理器打开一个目录或文件。
func openPath(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = hidewin.Command("explorer", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}
