//go:build !windows

package ssid

// Current returns the Wi-Fi SSID (unsupported on this platform).
func Current() (string, error) { return "", nil }
