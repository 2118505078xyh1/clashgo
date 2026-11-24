//go:build !linux && !windows
// +build !linux,!windows

package procinfo

// Lookup 在该平台暂未实现。
func Lookup(network, ip string, port uint16) string { return "" }
