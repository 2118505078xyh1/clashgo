package main

import "embed"

// 图标编译进二进制，安装后不依赖外部资源文件。
//
//go:embed resources/tray.png resources/tray-light.png resources/tray-dark.png resources/app-icon.png resources/app-icon.ico
var icons embed.FS

// 加载托盘图标（彩色）。
func loadTrayIcon() []byte {
	b, err := icons.ReadFile("resources/tray.png")
	if err != nil {
		return nil
	}
	return b
}

// 加载窗口/任务栏图标。
func loadAppIcon() []byte {
	b, err := icons.ReadFile("resources/app-icon.png")
	if err != nil {
		return nil
	}
	return b
}
