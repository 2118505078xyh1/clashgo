//go:build windows

package service

import (
	"clashgo/internal/hidewin"
	"fmt"
	"strings"
)

const serviceName = "ClashGoService"
const displayName = "ClashGo Service"

// IsAdmin reports whether the process has administrator privileges.
func IsAdmin() bool {
	return userIsAdmin()
}

// RunService runs as a Windows service. It blocks until stop signal.
// The service simply hosts the 自研内核 core; config reload is handled by the
// main app writing the runtime config and signaling via a named pipe.
func RunService() error {
	if !isWindowsService() {
		return fmt.Errorf("not running as a Windows service")
	}
	return runService(serviceName, &clashgoService{})
}

type clashgoService struct{}

func (s *clashgoService) Execute(args []string, req <-chan svcChangeRequest, status chan<- svcStatus) (bool, uint32) {
	const cmdsAccepted = serviceAcceptStop | serviceAcceptShutdown
	status <- svcStatus{State: serviceStartPending}
	// The service keeps the process alive; core lifecycle is managed by the
	// embedded kernel from the main app's runtime config.
	status <- svcStatus{State: serviceRunning, Accepts: cmdsAccepted}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case serviceControlStop, serviceControlShutdown:
				status <- svcStatus{State: serviceStopPending}
				return false, 0
			case serviceControlInterrogate:
				status <- c.CurrentStatus
			}
		}
	}
}

func isWindowsService() bool {
	return runningAsService()
}

// InstallService registers the service with the SCM using sc.exe.
func InstallService(exePath string) error {
	if !IsAdmin() {
		return fmt.Errorf("administrator privileges required to install service")
	}
	cmd := hidewin.Command("sc", "create", serviceName,
		"binPath=", strconvQuote(exePath+" --service"),
		"DisplayName=", strconvQuote(displayName),
		"start= auto")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UninstallService removes the service from the SCM.
func UninstallService() error {
	if !IsAdmin() {
		return fmt.Errorf("administrator privileges required to uninstall service")
	}
	cmd := hidewin.Command("sc", "delete", serviceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StartService starts the service via sc.exe.
func StartService() error {
	cmd := hidewin.Command("sc", "start", serviceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc start: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StopService stops the service.
func StopService() error {
	cmd := hidewin.Command("sc", "stop", serviceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc stop: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func strconvQuote(s string) string { return `"` + s + `"` }
