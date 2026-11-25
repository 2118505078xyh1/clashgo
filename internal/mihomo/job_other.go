//go:build !windows

package mihomo

import "os/exec"

// attachToJob 在非 Windows 平台上不做任何事。
func attachToJob(cmd *exec.Cmd) {}
