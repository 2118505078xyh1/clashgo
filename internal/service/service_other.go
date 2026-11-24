//go:build !windows

package service

func RunService() error                   { return nil }
func InstallService(exePath string) error { return nil }
func UninstallService() error             { return nil }
func StartService() error                 { return nil }
func StopService() error                  { return nil }
