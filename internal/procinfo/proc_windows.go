//go:build windows
// +build windows

package procinfo

// Lookup 在 Windows 下暂未实现进程反查（需 Toolhelp32 + WPF 表）。
// 返回空表示未知进程，PROCESS-NAME 规则在这种情况下不匹配。
func Lookup(network, ip string, port uint16) string { return "" }
