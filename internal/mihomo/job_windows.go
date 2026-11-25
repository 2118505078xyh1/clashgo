//go:build windows

package mihomo

import (
	"os/exec"
	"syscall"
	"unsafe"
)

// Job Object 让内核子进程随 ClashGo 一起结束。
//
// 为什么需要：ClashGo 被任务管理器强杀或崩溃时，OnBeforeQuit 不会执行，
// mihomo 就变成孤儿进程继续占用 7897/9097 端口。把子进程放进 Job Object
// 并设置 KILL_ON_JOB_CLOSE 后，父进程一死，Windows 内核会自动结束它。
var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW   = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJob = kernel32.NewProc("AssignProcessToJobObject")
	procSetInformationJob  = kernel32.NewProc("SetInformationJobObject")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
)

// JOB_OBJECT_EXTENDED_LIMIT_INFORMATION
type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioInfo
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioInfo struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	OtherBytesCount     uint64
}

const (
	jobObjectInfoClassExtendedLimit = 9
	jobObjectLimitKillOnJobClose    = 0x00002000
)

// attachToJob 把子进程放进当前进程的 Job Object（如果可用）。
//
// 失败不致命：内核仍然可以通过正常退出路径被结束，只是失去了
// "父进程被强杀时自动结束" 的保险。
func attachToJob(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	job, _, _ := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		return
	}
	info := jobObjectExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if ret, _, _ := procSetInformationJob.Call(job, jobObjectInfoClassExtendedLimit,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); ret == 0 {
		procCloseHandle.Call(job)
		return
	}
	// 把子进程加入 job。
	if ret, _, _ := procAssignProcessToJob.Call(job, uintptr(cmd.Process.Pid)); ret == 0 {
		procCloseHandle.Call(job)
		return
	}
	// handle 需要保持打开，否则 job 会被立即关闭。
	// 这里故意不关闭：它随 ClashGo 进程一起消失。
}
