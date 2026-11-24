//go:build !windows
// +build !windows

package minikernel

import "fmt"

// tapDevice 在非 Windows 平台的占位实现（TUN 当前仅 Windows 完整支持）。
type tapDevice struct{}

func openTAP(name string) (*tapDevice, error) {
	return nil, fmt.Errorf("TUN 当前仅支持 Windows 平台")
}

// ProbeTAP 在非 Windows 平台直接报告不支持。
func ProbeTAP() (string, error) {
	return "", fmt.Errorf("TUN 当前仅支持 Windows 平台")
}

func (d *tapDevice) configure(ip, mask, gateway [4]byte, mtu int) error { return nil }
func (d *tapDevice) Read(b []byte) (int, error)                         { return 0, fmt.Errorf("no TUN") }
func (d *tapDevice) Write(b []byte) (int, error)                        { return 0, fmt.Errorf("no TUN") }
func (d *tapDevice) Close() error                                       { return nil }
