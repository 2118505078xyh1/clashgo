//go:build windows
// +build windows

package minikernel

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tapIOCTLGetMAC         = 0x00000001
	tapIOCTLSetMediaStatus = 0x00000006
	tapIOCTLConfigTUN      = 0x0000000b
	tapIOCTLSetMTU         = 0x0000000e
)

// tapDevice 是通过 syscall 直接打开的 TAP-Windows 适配器。
type tapDevice struct {
	handle syscall.Handle
}

// ProbeTAP 只做前置条件探测：枚举 TAP 适配器并尝试打开它（不改配置）。
// 返回适配器名；失败时错误里会区分"没装适配器"和"无管理员权限"。
// 供 verify tun 与实机测试使用。
func ProbeTAP() (string, error) {
	guid, err := findTAPGUID("")
	if err != nil {
		return "", err
	}
	path, err := syscall.UTF16PtrFromString(`\\.\Global\` + guid + `.tap`)
	if err != nil {
		return "", err
	}
	handle, err := syscall.CreateFile(path,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_SYSTEM|syscall.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return "", fmt.Errorf("open TAP %s: %w（请以管理员身份运行）", guid, err)
	}
	syscall.CloseHandle(handle)
	return guid, nil
}

// openTAP 打开名为 name 的 TAP 适配器。name 为空时打开第一个可用的。
func openTAP(name string) (*tapDevice, error) {
	guid, err := findTAPGUID(name)
	if err != nil {
		return nil, err
	}
	path, err := syscall.UTF16PtrFromString(`\\.\Global\` + guid + `.tap`)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(path,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_SYSTEM|syscall.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, fmt.Errorf("open TAP %s: %w", guid, err)
	}
	dev := &tapDevice{handle: handle}

	// 设置媒体状态为 connected（DWORD=1）。
	var status uint32 = 1
	var ret uint32
	if err := syscall.DeviceIoControl(handle, tapIOCTLSetMediaStatus,
		(*byte)(unsafe.Pointer(&status)), 4, nil, 0, &ret, nil); err != nil {
		syscall.CloseHandle(handle)
		return nil, fmt.Errorf("TAP set media status: %w", err)
	}
	return dev, nil
}

// findTAPGUID 从注册表找到 TAP 适配器的 GUID。
func findTAPGUID(wanted string) (string, error) {
	const netAdapterKey = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}`
	keyPtr, err := syscall.UTF16PtrFromString(netAdapterKey)
	if err != nil {
		return "", err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, keyPtr, 0, syscall.KEY_READ, &key); err != nil {
		return "", fmt.Errorf("open network adapter registry: %w", err)
	}
	defer syscall.RegCloseKey(key)

	var i uint32
	for i = 0; i < 256; i++ {
		subName := fmt.Sprintf("%s\\%08d", netAdapterKey, i)
		subPtr, e := syscall.UTF16PtrFromString(subName)
		if e != nil {
			continue
		}
		var subKey syscall.Handle
		if e := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subPtr, 0, syscall.KEY_READ, &subKey); e != nil {
			continue
		}
		// 读取 Connection 子键的 Name（适配器名称）。
		guid := readRegString(subKey, "")
		syscall.RegCloseKey(subKey)
		if guid == "" {
			continue
		}
		connPtr, e := syscall.UTF16PtrFromString(subName + `\Connection`)
		if e != nil {
			continue
		}
		var connKey syscall.Handle
		if e := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, connPtr, 0, syscall.KEY_READ, &connKey); e != nil {
			continue
		}
		name := readRegString(connKey, "Name")
		syscall.RegCloseKey(connKey)
		if wanted == "" || strings.EqualFold(name, wanted) || strings.EqualFold(guid, wanted) {
			return guid, nil
		}
	}
	return "", fmt.Errorf("no TAP adapter found (name=%q)", wanted)
}

// readRegString 读取注册表字符串值。
func readRegString(key syscall.Handle, valueName string) string {
	var namePtr *uint16
	if valueName != "" {
		namePtr, _ = syscall.UTF16PtrFromString(valueName)
	}
	var buf [512]uint16
	n := uint32(len(buf))
	var typ uint32
	if err := syscall.RegQueryValueEx(key, namePtr, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf[:n/2])
}

// configure 配置 TAP 的 IPv4 地址、掩码、网关，并添加路由。
func (d *tapDevice) configure(ip, mask, gateway [4]byte, mtu int) error {
	// CONFIG_TUN 结构：localIP, remoteIP(netmask), gateway —— 各 4 字节，小端。
	in := [12]byte{
		ip[0], ip[1], ip[2], ip[3],
		mask[0], mask[1], mask[2], mask[3],
		gateway[0], gateway[1], gateway[2], gateway[3],
	}
	var ret uint32
	if err := syscall.DeviceIoControl(d.handle, tapIOCTLConfigTUN,
		&in[0], uint32(len(in)), nil, 0, &ret, nil); err != nil {
		return fmt.Errorf("TAP config tun: %w", err)
	}
	if mtu > 0 {
		var m uint32 = uint32(mtu)
		if err := syscall.DeviceIoControl(d.handle, tapIOCTLSetMTU,
			(*byte)(unsafe.Pointer(&m)), 4, nil, 0, &ret, nil); err != nil {
			// MTU 设置失败不致命，忽略。
			_ = err
		}
	}
	return nil
}

func (d *tapDevice) Read(b []byte) (int, error) {
	var done uint32
	err := syscall.ReadFile(d.handle, b, &done, nil)
	return int(done), err
}

func (d *tapDevice) Write(b []byte) (int, error) {
	var done uint32
	err := syscall.WriteFile(d.handle, b, &done, nil)
	return int(done), err
}

func (d *tapDevice) Close() error { return syscall.CloseHandle(d.handle) }
