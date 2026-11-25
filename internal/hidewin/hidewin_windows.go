//go:build windows

// Package hidewin provides helpers to run child processes without flashing a
// console window (important for a GUI-only app on Windows).
package hidewin

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW 让子进程不分配控制台窗口。
//
// HideWindow 只隐藏启动瞬间的窗口闪现；如果子进程本身是控制台程序
// (如 mihomo.exe)，它仍会弹出黑色控制台窗口。CREATE_NO_WINDOW 才是
// 彻底不创建控制台的正确做法。
const createNoWindow = 0x08000000

// Command returns an exec.Cmd configured to hide its console window.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// CommandNoConsole returns an exec.Cmd that runs without any console window.
//
// 用于启动控制台子进程（mihomo 等），避免在 GUI 程序运行时弹出黑框。
func CommandNoConsole(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	return cmd
}

// Output runs the command hidden and returns stdout.
func Output(name string, args ...string) ([]byte, error) {
	return Command(name, args...).Output()
}

// Run runs the command hidden.
func Run(name string, args ...string) error {
	return Command(name, args...).Run()
}
