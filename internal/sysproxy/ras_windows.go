//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// This file mirrors what a reference GUI / a reference client do on Windows: besides the LAN
// settings in HKCU\...\Internet Settings, WinINet keeps a separate proxy
// configuration for every dial-up / VPN / broadband (RAS) connection. Setting
// only the registry leaves those connections without a proxy, so we enumerate
// them through rasapi32!RasEnumEntriesW and push the proxy settings into each
// one with wininet!InternetSetOptionW.

var (
	rasapi32       = syscall.NewLazyDLL("rasapi32.dll")
	rasEnumEntries = rasapi32.NewProc("RasEnumEntriesW")
)

const (
	// RAS / Win32 error codes used by RasEnumEntriesW.
	errorSuccess            = 0
	errorMoreData           = 234 // ERROR_MORE_DATA
	errorInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
	errorBufferTooSmall     = 603 // ERROR_BUFFER_TOO_SMALL (what RasEnumEntriesW returns)

	// WinINet option ids (wininet.h).
	internetOptionPerConnectionOption = 75 // INTERNET_OPTION_PER_CONNECTION_OPTION

	// INTERNET_PER_CONN_* option kinds (wininet.h).
	internetPerConnFlags       = 1 // INTERNET_PER_CONN_FLAGS
	internetPerConnProxyServer = 2 // INTERNET_PER_CONN_PROXY_SERVER
	internetPerConnProxyBypass = 3 // INTERNET_PER_CONN_PROXY_BYPASS
	// NOTE: 5 is INTERNET_PER_CONN_AUTODISCOVERY_FLAGS, not PROXY_BYPASS.
	// Some notes quote "BYPASS=5"; that is wrong for wininet.h, so we use 3.

	// PROXY_TYPE_* flags for INTERNET_PER_CONN_FLAGS.
	proxyTypeDirect = 0x00000001
	proxyTypeProxy  = 0x00000002
)

// rasMaxEntryName is RAS_MaxEntryName from ras.h; szEntryName is therefore
// 257 WCHARs including the terminator. unsafe.Sizeof gives 520 bytes on both
// 32- and 64-bit Windows (4 + 257*2 = 518, rounded to DWORD alignment),
// which is exactly what RasEnumEntriesW expects in dwSize.
const rasMaxEntryName = 256

type rasEntryName struct {
	dwSize      uint32
	szEntryName [rasMaxEntryName + 1]uint16
}

// internetPerConnOption is INTERNET_PER_CONN_OPTIONW. The union in the C
// struct is represented by a uintptr holding either a DWORD (flags) or a
// pointer to a NUL-terminated wide string (server / bypass).
type internetPerConnOption struct {
	dwOption uint32
	value    uintptr
}

// internetPerConnOptionList is INTERNET_PER_CONN_OPTION_LISTW. Go inserts the
// same padding as the C compiler, so unsafe.Sizeof is the right dwSize/length.
type internetPerConnOptionList struct {
	dwSize        uint32
	pszConnection *uint16 // nil means the LAN connection
	dwOptionCount uint32
	dwOptionError uint32
	pOptions      *internetPerConnOption
}

// SetAllConnections applies the proxy to every Windows connection: the LAN
// settings first, then each RAS (dial-up / VPN / PPPoE) entry. Failures to
// enumerate RAS connections are not fatal — a machine without dial-up entries
// is a normal case — but individual per-connection failures are reported.
func SetAllConnections(enable bool, server, bypass string) error {
	if err := setLANOnly(enable, server, bypass); err != nil {
		return err
	}

	connections, err := enumRASConnections()
	if err != nil {
		// No phonebook / no dial-up entries: the LAN setting above is enough.
		return nil
	}
	var errs []error
	for _, name := range connections {
		if err := setConnectionOption(name, enable, server, bypass); err != nil {
			errs = append(errs, fmt.Errorf("RAS connection %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// enumRASConnections returns the names of all RAS entries. It first probes
// with a nil buffer to learn the required size, then allocates and retries
// while RasEnumEntriesW reports ERROR_MORE_DATA / ERROR_BUFFER_TOO_SMALL.
func enumRASConnections() ([]string, error) {
	if err := rasapi32.Load(); err != nil {
		// rasapi32 is absent on some Windows SKUs; treat as "no RAS entries".
		return nil, nil
	}

	entrySize := uint32(unsafe.Sizeof(rasEntryName{}))
	var size, count uint32
	ret, _, _ := rasEnumEntries.Call(
		0, // reserved, must be NULL
		0, // default phonebook
		0, // probe: no buffer
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&count)),
	)
	if ret == errorSuccess {
		return nil, nil
	}
	if ret != errorBufferTooSmall && ret != errorMoreData && ret != errorInsufficientBuffer {
		return nil, fmt.Errorf("RasEnumEntriesW (probe): %w", syscall.Errno(ret))
	}

	n := count
	if needed := size / entrySize; needed > n {
		n = needed
	}
	if n == 0 {
		return nil, nil
	}

	for attempt := 0; attempt < 8; attempt++ {
		entries := make([]rasEntryName, n)
		for i := range entries {
			entries[i].dwSize = entrySize
		}
		size = uint32(len(entries)) * entrySize
		count = 0
		ret, _, _ := rasEnumEntries.Call(
			0,
			0,
			uintptr(unsafe.Pointer(&entries[0])),
			uintptr(unsafe.Pointer(&size)),
			uintptr(unsafe.Pointer(&count)),
		)
		switch ret {
		case errorSuccess:
			names := make([]string, 0, count)
			for i := uint32(0); i < count && i < uint32(len(entries)); i++ {
				if name := syscall.UTF16ToString(entries[i].szEntryName[:]); name != "" {
					names = append(names, name)
				}
			}
			return names, nil
		case errorBufferTooSmall, errorMoreData, errorInsufficientBuffer:
			next := size / entrySize
			if next <= n {
				next = n * 2
			}
			if next > 4096 {
				next = 4096
			}
			n = next
			continue
		default:
			return nil, fmt.Errorf("RasEnumEntriesW: %w", syscall.Errno(ret))
		}
	}
	return nil, errors.New("RasEnumEntriesW: buffer grew too large")
}

// setConnectionOption writes FLAGS / PROXY_SERVER / PROXY_BYPASS into one
// connection's WinINet per-connection store. An empty connection name means
// the LAN connection; we use that for dial-up entries only here.
func setConnectionOption(connection string, enable bool, server, bypass string) error {
	if err := wininet.Load(); err != nil {
		return fmt.Errorf("load wininet: %w", err)
	}

	connPtr, err := syscall.UTF16PtrFromString(connection)
	if err != nil {
		return err
	}
	serverPtr, err := syscall.UTF16PtrFromString(server)
	if err != nil {
		return err
	}
	bypassPtr, err := syscall.UTF16PtrFromString(bypass)
	if err != nil {
		return err
	}

	flags := uint32(proxyTypeDirect)
	if enable {
		flags = proxyTypeDirect | proxyTypeProxy
	}
	options := []internetPerConnOption{
		{dwOption: internetPerConnFlags, value: uintptr(flags)},
		{dwOption: internetPerConnProxyServer, value: uintptr(unsafe.Pointer(serverPtr))},
		{dwOption: internetPerConnProxyBypass, value: uintptr(unsafe.Pointer(bypassPtr))},
	}
	list := internetPerConnOptionList{
		dwSize:        uint32(unsafe.Sizeof(internetPerConnOptionList{})),
		pszConnection: connPtr,
		dwOptionCount: uint32(len(options)),
		pOptions:      &options[0],
	}

	ret, _, callErr := internetSetOption.Call(
		0,
		internetOptionPerConnectionOption,
		uintptr(unsafe.Pointer(&list)),
		uintptr(unsafe.Sizeof(list)),
	)
	// The pointers above are stored as uintptr, which hides them from the GC.
	// Keep them alive until the syscall has returned.
	runtime.KeepAlive(connPtr)
	runtime.KeepAlive(serverPtr)
	runtime.KeepAlive(bypassPtr)
	runtime.KeepAlive(options)
	if ret == 0 {
		return fmt.Errorf("InternetSetOptionW(per-connection): %w", callErr)
	}
	return nil
}
