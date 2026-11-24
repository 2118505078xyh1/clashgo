//go:build !windows

package sysproxy

// SetAllConnections is a no-op wrapper on non-Windows platforms. There is no
// RAS / WinINet per-connection store there, so the platform's setOS (gsettings
// on Linux) remains the whole implementation.
func SetAllConnections(enable bool, server, bypass string) error {
	return setOS(enable, server, bypass)
}
