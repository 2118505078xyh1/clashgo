// Package diagnostic collects environment info for support bundles.
package diagnostic

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"clashgo/internal/paths"
)

// Info is a snapshot of app and system information.
type Info struct {
	AppVersion  string
	GoVersion   string
	OS          string
	Arch        string
	Hostname    string
	Interfaces  []InterfaceInfo
	DataDir     string
	CollectedAt string
}

// InterfaceInfo describes a network interface.
type InterfaceInfo struct {
	Name string
	IPs  []string
	MAC  string
}

// Collect gathers diagnostic information.
func Collect(appVersion string) Info {
	hostname, _ := os.Hostname()
	var ifaces []InterfaceInfo
	all, _ := net.Interfaces()
	for _, iface := range all {
		addrs, _ := iface.Addrs()
		var ips []string
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
		ifaces = append(ifaces, InterfaceInfo{
			Name: iface.Name, MAC: iface.HardwareAddr.String(), IPs: ips,
		})
	}
	return Info{
		AppVersion:  appVersion,
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Hostname:    hostname,
		Interfaces:  ifaces,
		DataDir:     paths.Home,
		CollectedAt: time.Now().Format("2006-01-02 15:04:05"),
	}
}

// Text renders the diagnostic snapshot as a human-readable string.
func (i Info) Text() string {
	var b strings.Builder
	b.WriteString("=== ClashGo Diagnostic Info ===\n")
	fmt.Fprintf(&b, "App: %s\nGo: %s\nOS/Arch: %s/%s\nHost: %s\nData: %s\nTime: %s\n\n",
		i.AppVersion, i.GoVersion, i.OS, i.Arch, i.Hostname, i.DataDir, i.CollectedAt)
	b.WriteString("--- Network Interfaces ---\n")
	for _, iface := range i.Interfaces {
		fmt.Fprintf(&b, "%s  MAC=%s\n", iface.Name, iface.MAC)
		for _, ip := range iface.IPs {
			fmt.Fprintf(&b, "  %s\n", ip)
		}
	}
	return b.String()
}
