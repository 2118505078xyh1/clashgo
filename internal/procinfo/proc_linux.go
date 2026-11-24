//go:build linux
// +build linux

// Package procinfo 提供按本地 socket 地址反查进程名的能力（纯标准库）。
package procinfo

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Lookup 根据协议(tcp/udp)和本地地址(ip:port)反查进程名。
func Lookup(network, ip string, port uint16) string {
	if network == "tcp" {
		return lookupTCP(ip, port)
	}
	return ""
}

func inodeOf(network, ip string, port uint16) string {
	path := "/proc/net/" + network
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	portHex := strconv.FormatUint(uint64(port), 16)
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		state := fields[3]
		if network == "tcp" && state != "0A" { // TCP_ESTABLISHED
			continue
		}
		parts := strings.Split(local, ":")
		if len(parts) != 2 || parts[1] != portHex {
			continue
		}
		return fields[9] // inode
	}
	return ""
}

func lookupTCP(ip string, port uint16) string {
	inode := inodeOf("tcp", ip, port)
	if inode == "" {
		return ""
	}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fdDir := "/proc/" + pid + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]") == inode {
				return readComm(pid)
			}
		}
	}
	return ""
}

func readComm(pid string) string {
	b, err := os.ReadFile("/proc/" + pid + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
