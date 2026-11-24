//go:build windows

// Package hidewin provides helpers to run child processes without flashing a
// console window (important for a GUI-only app on Windows).
package hidewin

import (
	"os/exec"
	"syscall"
)

// Command returns an exec.Cmd configured to hide its console window.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// Output runs the command hidden and returns stdout.
func Output(name string, args ...string) ([]byte, error) {
	return Command(name, args...).Output()
}

// Run runs the command hidden.
func Run(name string, args ...string) error {
	return Command(name, args...).Run()
}
