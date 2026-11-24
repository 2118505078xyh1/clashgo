//go:build windows

// Package winreg is a minimal Windows registry wrapper built only on the Go
// standard library's syscall package. It provides the small subset of the
// golang.org/x/sys/windows/registry API used by this project, so those
// callers do not need the x/sys dependency.
package winreg

import (
	"encoding/binary"
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

// Key is an open handle to a registry key.
type Key syscall.Handle

// Root keys and access masks, named to match x/sys/windows/registry.
const (
	CURRENT_USER  Key = syscall.HKEY_CURRENT_USER
	LOCAL_MACHINE Key = syscall.HKEY_LOCAL_MACHINE

	QUERY_VALUE = syscall.KEY_QUERY_VALUE
	SET_VALUE   = syscall.KEY_SET_VALUE
)

// ErrWrongType is returned when a value is not of the requested type.
var ErrWrongType = errors.New("winreg: wrong value type")

var (
	advapi32        = syscall.NewLazyDLL("advapi32.dll")
	procSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procDeleteValue = advapi32.NewProc("RegDeleteValueW")
)

// OpenKey opens the named subkey of k with the requested access.
func OpenKey(k Key, path string, access uint32) (Key, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.Handle(k), pathp, 0, access, &h); err != nil {
		runtime.KeepAlive(pathp)
		return 0, err
	}
	runtime.KeepAlive(pathp)
	return Key(h), nil
}

// Close closes an open key.
func (k Key) Close() error { return syscall.RegCloseKey(syscall.Handle(k)) }

// SetStringValue writes a REG_SZ value.
func (k Key) SetStringValue(name, value string) error {
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	return k.setValue(name, syscall.REG_SZ, unsafe.Pointer(&data[0]), uint32(len(data)*2))
}

// SetDWordValue writes a REG_DWORD value.
func (k Key) SetDWordValue(name string, value uint32) error {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	return k.setValue(name, syscall.REG_DWORD, unsafe.Pointer(&data[0]), uint32(len(data)))
}

// setValue calls RegSetValueExW. The API returns the Windows error code
// directly as its return value (rather than through GetLastError).
func (k Key) setValue(name string, typ uint32, data unsafe.Pointer, dataLen uint32) error {
	namep, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r1, _, _ := procSetValueEx.Call(
		uintptr(k),
		uintptr(unsafe.Pointer(namep)),
		0,
		uintptr(typ),
		uintptr(data),
		uintptr(dataLen),
	)
	runtime.KeepAlive(namep)
	runtime.KeepAlive(data)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// DeleteValue removes a value from the key.
func (k Key) DeleteValue(name string) error {
	namep, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r1, _, _ := procDeleteValue.Call(uintptr(k), uintptr(unsafe.Pointer(namep)))
	runtime.KeepAlive(namep)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// GetStringValue reads a REG_SZ or REG_EXPAND_SZ value. It returns the raw
// value type so callers can distinguish a missing value from a wrong type.
func (k Key) GetStringValue(name string) (string, uint32, error) {
	data, typ, err := k.getValue(name)
	if err != nil {
		return "", typ, err
	}
	switch typ {
	case syscall.REG_SZ, syscall.REG_EXPAND_SZ:
		return decodeString(data), typ, nil
	default:
		return "", typ, ErrWrongType
	}
}

// GetIntegerValue reads a REG_DWORD, REG_QWORD or REG_DWORD_BIG_ENDIAN value.
func (k Key) GetIntegerValue(name string) (uint64, uint32, error) {
	data, typ, err := k.getValue(name)
	if err != nil {
		return 0, typ, err
	}
	switch typ {
	case syscall.REG_DWORD:
		if len(data) < 4 {
			return 0, typ, ErrWrongType
		}
		return uint64(binary.LittleEndian.Uint32(data[:4])), typ, nil
	case syscall.REG_QWORD:
		if len(data) < 8 {
			return 0, typ, ErrWrongType
		}
		return binary.LittleEndian.Uint64(data[:8]), typ, nil
	case syscall.REG_DWORD_BIG_ENDIAN:
		if len(data) < 4 {
			return 0, typ, ErrWrongType
		}
		return uint64(binary.BigEndian.Uint32(data[:4])), typ, nil
	default:
		return 0, typ, ErrWrongType
	}
}

// getValue performs the usual two-pass RegQueryValueEx: first learn the
// buffer size and type, then read the bytes.
func (k Key) getValue(name string) ([]byte, uint32, error) {
	namep, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, err
	}
	var typ, n uint32
	if err := syscall.RegQueryValueEx(syscall.Handle(k), namep, nil, &typ, nil, &n); err != nil {
		runtime.KeepAlive(namep)
		return nil, typ, err
	}
	if n == 0 {
		runtime.KeepAlive(namep)
		return nil, typ, nil
	}
	buf := make([]byte, n)
	if err := syscall.RegQueryValueEx(syscall.Handle(k), namep, nil, &typ, &buf[0], &n); err != nil {
		runtime.KeepAlive(namep)
		runtime.KeepAlive(buf)
		return nil, typ, err
	}
	runtime.KeepAlive(namep)
	runtime.KeepAlive(buf)
	if n > uint32(len(buf)) {
		n = uint32(len(buf))
	}
	return buf[:n], typ, nil
}

// decodeString converts UTF-16LE registry bytes to a Go string.
func decodeString(data []byte) string {
	n := len(data) / 2
	if n == 0 {
		return ""
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	return syscall.UTF16ToString(u)
}
