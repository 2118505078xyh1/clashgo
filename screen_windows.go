package main

import "syscall"

var (
	user32           = syscall.NewLazyDLL("user32.dll")
	getSystemMetrics = user32.NewProc("GetSystemMetrics")
)

const (
	smCXSCREEN = 0
	smCYSCREEN = 1
)

// 取主屏幕尺寸，用于约束窗口位置，避免恢复到屏幕外。
func screenSize() (int, int) {
	w, _, _ := getSystemMetrics.Call(smCXSCREEN)
	h, _, _ := getSystemMetrics.Call(smCYSCREEN)
	return int(w), int(h)
}
