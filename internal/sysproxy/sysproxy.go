// Package sysproxy manages the operating system's HTTP/SOCKS proxy settings.
package sysproxy

import "strings"

// Status describes the current system proxy setting.
type Status struct {
	Enable bool   `json:"enable"`
	Server string `json:"server"`
	Bypass string `json:"bypass"`
}

// Set enables or disables the system proxy for the given address and bypass list.
func Set(enable bool, server, bypass string) error {
	return setOS(enable, server, bypass)
}

// GetStatus reads the current system proxy setting (guard Applier support).
func GetStatus() (*Status, error) { return getOS() }

// Set applies or clears the system proxy (guard Applier support).
func Apply(enable bool, server, bypass string) error { return setOS(enable, server, bypass) }

// PointsTo 判断当前系统代理是否仍然指向本机指定端口。
// 退出清理时先做这个检查，避免把用户自己设置的其他代理一起关掉。
func PointsTo(port int) bool {
	st, err := GetStatus()
	if err != nil || st == nil || !st.Enable {
		return false
	}
	return serverMatchesPort(st.Server, port)
}

// serverMatchesPort 判断代理地址串是否指向本机指定端口。
// 兼容 "127.0.0.1:7897" 和 "http=127.0.0.1:7897;https=127.0.0.1:7897" 两种写法。
func serverMatchesPort(server string, port int) bool {
	want := itoa(port)
	for _, part := range strings.FieldsFunc(server, func(r rune) bool {
		return r == ';' || r == ',' || r == ' '
	}) {
		if idx := strings.LastIndex(part, "="); idx >= 0 {
			part = part[idx+1:]
		}
		host, portStr, ok := splitHostPort(part)
		if !ok || portStr != want {
			continue
		}
		switch strings.ToLower(host) {
		case "127.0.0.1", "localhost", "[::1]", "::1":
			return true
		}
	}
	return false
}

// splitHostPort 拆出代理地址里的主机与端口，兼容 IPv6 的 "[::1]:7897" 写法。
func splitHostPort(addr string) (string, string, bool) {
	if strings.HasPrefix(addr, "[") {
		if end := strings.Index(addr, "]"); end >= 0 {
			host := addr[:end+1]
			rest := addr[end+1:]
			if strings.HasPrefix(rest, ":") {
				return host, rest[1:], true
			}
			return host, "", false
		}
		return "", "", false
	}
	return strings.Cut(addr, ":")
}

// ClearIfPointsTo 在系统代理仍指向指定端口时才关闭它，返回是否执行了清理。
func ClearIfPointsTo(port int) (bool, error) {
	if !PointsTo(port) {
		return false, nil
	}
	if err := Set(false, "", ""); err != nil {
		return true, err
	}
	return true, nil
}

// itoa 是极简整数转字符串，避免为此引入额外依赖。
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
