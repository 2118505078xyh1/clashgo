//go:build windows

package service

// This file implements the small subset of the Windows Service Control
// Manager (SCM) protocol that the service package needs, using only the
// standard library. It replaces golang.org/x/sys/windows and
// golang.org/x/sys/windows/svc.
//
// Flow:
//   - runService builds a SERVICE_TABLE_ENTRY table and calls
//     StartServiceCtrlDispatcherW. The SCM then calls our ServiceMain on a
//     dedicated thread.
//   - ServiceMain registers a control handler with RegisterServiceCtrlHandlerExW
//     and reports lifecycle states with SetServiceStatus.
//   - Control codes (STOP / SHUTDOWN / INTERROGATE) are forwarded to the
//     handler's Execute method via channels, mirroring the old svc.Handler API.

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// ---- Win32 constants -------------------------------------------------------

const (
	serviceWin32OwnProcess = 0x00000010

	serviceStopped         = 0x00000001
	serviceStartPending    = 0x00000002
	serviceStopPending     = 0x00000003
	serviceRunning         = 0x00000004
	serviceContinuePending = 0x00000005
	servicePausePending    = 0x00000006
	servicePaused          = 0x00000007

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005

	processQueryLimitedInformation = 0x1000

	securityBuiltinDomainRid = 0x00000020
	domainAliasRidAdmins     = 0x00000220
)

// ---- Win32 structures ------------------------------------------------------

// serviceTableEntry mirrors SERVICE_TABLE_ENTRY. Both fields are pointers, so
// two uintptrs give the correct layout on 32- and 64-bit Windows.
type serviceTableEntry struct {
	name uintptr // LPTSTR  lpServiceName
	proc uintptr // SERVICE_MAIN_FUNCTION lpServiceProc
}

// win32ServiceStatus mirrors SERVICE_STATUS (seven DWORDs, 28 bytes).
type win32ServiceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

// processBasicInformation mirrors PROCESS_BASIC_INFORMATION. Using uint for
// every field matches the C layout on both 32- and 64-bit Windows (the 4-byte
// fields are padded to pointer size on x64).
type processBasicInformation struct {
	exitStatus                   uint
	pebBaseAddress               uintptr
	affinityMask                 uint
	basePriority                 uint
	uniqueProcessID              uint
	inheritedFromUniqueProcessID uint
}

// ---- Win32 API declarations ------------------------------------------------

var (
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modNtdll    = syscall.NewLazyDLL("ntdll.dll")

	procStartServiceCtrlDispatcher = modAdvapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterCtrlHandlerEx      = modAdvapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus           = modAdvapi32.NewProc("SetServiceStatus")
	procAllocateAndInitializeSid   = modAdvapi32.NewProc("AllocateAndInitializeSid")
	procCheckTokenMembership       = modAdvapi32.NewProc("CheckTokenMembership")
	procFreeSid                    = modAdvapi32.NewProc("FreeSid")

	procGetCurrentProcess          = modKernel32.NewProc("GetCurrentProcess")
	procOpenProcess                = modKernel32.NewProc("OpenProcess")
	procCloseHandle                = modKernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")

	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
)

// ---- Types exposed to service_windows.go -----------------------------------

// svcStatus mirrors the small part of svc.Status used by the service.
type svcStatus struct {
	State      uint32
	Accepts    uint32
	CheckPoint uint32
	WaitHint   uint32
}

// svcChangeRequest mirrors svc.ChangeRequest.
type svcChangeRequest struct {
	Cmd           uint32
	CurrentStatus svcStatus
}

// svcHandler is the simplified replacement for svc.Handler.
type svcHandler interface {
	Execute(args []string, req <-chan svcChangeRequest, status chan<- svcStatus) (bool, uint32)
}

// Globals keep callback pointers, strings and the dispatch table alive for the
// lifetime of the process. Windows holds raw pointers to all of them.
var (
	activeServiceHandler svcHandler
	serviceNameUTF16     *uint16
	serviceTable         [2]serviceTableEntry
	handlerControlCh     chan uint32

	serviceMainCallback    = syscall.NewCallback(serviceMain)
	serviceControlCallback = syscall.NewCallback(serviceCtrlHandler)
)

// ---- Public helpers --------------------------------------------------------

// runService registers with the SCM and blocks until the service is stopped.
func runService(name string, h svcHandler) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	activeServiceHandler = h
	handlerControlCh = make(chan uint32, 16)
	serviceNameUTF16 = n
	serviceTable[0] = serviceTableEntry{
		name: uintptr(unsafe.Pointer(serviceNameUTF16)),
		proc: serviceMainCallback,
	}
	serviceTable[1] = serviceTableEntry{} // required NULL terminator

	r1, _, e1 := syscall.SyscallN(
		procStartServiceCtrlDispatcher.Addr(),
		uintptr(unsafe.Pointer(&serviceTable[0])),
	)
	if r1 == 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

// runningAsService reports whether the current process was launched by the
// SCM. A service's parent process is services.exe; checking that is both
// accurate and free of the x/sys dependency.
func runningAsService() bool {
	cur, _, _ := syscall.SyscallN(procGetCurrentProcess.Addr())
	if cur == 0 {
		return false
	}

	var pbi processBasicInformation
	nt, _, _ := syscall.SyscallN(
		procNtQueryInformationProcess.Addr(),
		cur,
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		0,
	)
	if nt != 0 || pbi.inheritedFromUniqueProcessID == 0 {
		return false
	}

	parent, _, _ := syscall.SyscallN(
		procOpenProcess.Addr(),
		processQueryLimitedInformation,
		0,
		uintptr(pbi.inheritedFromUniqueProcessID),
	)
	if parent == 0 {
		return false
	}
	defer syscall.SyscallN(procCloseHandle.Addr(), parent)

	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	ok, _, _ := syscall.SyscallN(
		procQueryFullProcessImageNameW.Addr(),
		parent,
		0, // 0 = process image path
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ok == 0 || size == 0 || size > uint32(len(buf)) {
		return false
	}
	return strings.EqualFold(filepath.Base(syscall.UTF16ToString(buf[:size])), "services.exe")
}

// userIsAdmin checks membership in the local Administrators group using raw
// advapi32 calls (replaces windows.AllocateAndInitializeSid / Token.IsMember).
func userIsAdmin() bool {
	// SECURITY_NT_AUTHORITY = {0,0,0,0,0,5}
	authority := [6]byte{0, 0, 0, 0, 0, 5}
	var sid uintptr
	ok, _, _ := syscall.SyscallN(
		procAllocateAndInitializeSid.Addr(),
		uintptr(unsafe.Pointer(&authority)),
		2, // sub-authority count
		securityBuiltinDomainRid,
		domainAliasRidAdmins,
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&sid)),
	)
	if ok == 0 || sid == 0 {
		return false
	}
	defer syscall.SyscallN(procFreeSid.Addr(), sid)

	var isMember int32
	ok, _, _ = syscall.SyscallN(
		procCheckTokenMembership.Addr(),
		0, // current effective token
		sid,
		uintptr(unsafe.Pointer(&isMember)),
	)
	return ok != 0 && isMember != 0
}

// ---- SCM callbacks ---------------------------------------------------------

// serviceMain has the signature of SERVICE_MAIN_FUNCTION:
//
//	VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
//
// Typed pointer arguments are supported by syscall.NewCallback and keep the
// raw SCM pointers visible to the GC.
func serviceMain(argc uint32, argv **uint16) uintptr {
	args := make([]string, 0, int(argc))
	if argc > 0 && argv != nil {
		for _, p := range unsafe.Slice(argv, int(argc)) {
			if p != nil {
				args = append(args, wideString(p))
			}
		}
	}

	statusHandle, _, _ := syscall.SyscallN(
		procRegisterCtrlHandlerEx.Addr(),
		uintptr(unsafe.Pointer(serviceNameUTF16)),
		serviceControlCallback,
		0, // lpContext
	)
	if statusHandle == 0 {
		return 0
	}

	setStatus(statusHandle, &win32ServiceStatus{
		serviceType:  serviceWin32OwnProcess,
		currentState: serviceStartPending,
		checkPoint:   1,
		waitHint:     5000,
	})

	reqCh := make(chan svcChangeRequest, 8)
	statusCh := make(chan svcStatus, 8)
	doneCh := make(chan uint32, 1)

	handler := activeServiceHandler
	go func() {
		_, exitCode := handler.Execute(args, reqCh, statusCh)
		doneCh <- exitCode
	}()

	current := svcStatus{State: serviceStartPending}
	for {
		select {
		case s := <-statusCh:
			current = s
			setStatus(statusHandle, &win32ServiceStatus{
				serviceType:      serviceWin32OwnProcess,
				currentState:     s.State,
				controlsAccepted: s.Accepts,
				checkPoint:       s.CheckPoint,
				waitHint:         s.WaitHint,
			})
		case control := <-handlerControlCh:
			req := svcChangeRequest{Cmd: control, CurrentStatus: current}
			select {
			case reqCh <- req:
			default: // handler is finishing; drop further control codes
			}
		case exitCode := <-doneCh:
			setStatus(statusHandle, &win32ServiceStatus{
				serviceType:   serviceWin32OwnProcess,
				currentState:  serviceStopped,
				win32ExitCode: exitCode,
			})
			return 0
		}
	}
}

// serviceCtrlHandler has the signature of HANDLER_FUNCTION_EX:
//
//	DWORD WINAPI HandlerEx(DWORD, DWORD, LPVOID, LPVOID)
func serviceCtrlHandler(control, eventType uint32, eventData, context unsafe.Pointer) uintptr {
	switch control {
	case serviceControlStop, serviceControlShutdown, serviceControlInterrogate:
		if ch := handlerControlCh; ch != nil {
			select {
			case ch <- control:
			default: // channel full; SCM can resend if needed
			}
		}
	}
	return 0 // NO_ERROR
}

// ---- small helpers ---------------------------------------------------------

func setStatus(handle uintptr, st *win32ServiceStatus) {
	syscall.SyscallN(procSetServiceStatus.Addr(), handle, uintptr(unsafe.Pointer(st)))
}

func wideString(p *uint16) string {
	if p == nil {
		return ""
	}
	// A NUL-terminated LPWSTR view; UTF16ToString stops at the terminator.
	return syscall.UTF16ToString(unsafe.Slice(p, 1<<20))
}
