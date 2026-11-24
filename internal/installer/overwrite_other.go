//go:build !windows

package installer

// 非 Windows 无需特殊覆盖处理。
func prepareOverwrite(installDir string, dataDir string) error { return nil }
