// Package sysproxy manages the operating system's HTTP/SOCKS proxy settings.
package sysproxy

// Status describes the current system proxy setting.
type Status struct {
	Enable bool   `json:"enable"`
	Server string `json:"server"`
	Bypass string `json:"bypass"`
}

// Set enables or disables the system proxy for the given address and bypass list.
func Set(enable bool, server, bypass string) error {
	return setOS(enable, server, bypass)
}

// GetStatus reads the current system proxy setting (guard Applier support).
func GetStatus() (*Status, error) { return getOS() }

// Set applies or clears the system proxy (guard Applier support).
func Apply(enable bool, server, bypass string) error { return setOS(enable, server, bypass) }
