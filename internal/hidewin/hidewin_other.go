//go:build !windows

package hidewin

import "os/exec"

// Command returns an exec.Cmd (no window concept on non-Windows).
func Command(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }

// Output runs the command and returns stdout.
func Output(name string, args ...string) ([]byte, error) { return Command(name, args...).Output() }

// Run runs the command.
func Run(name string, args ...string) error { return Command(name, args...).Run() }
