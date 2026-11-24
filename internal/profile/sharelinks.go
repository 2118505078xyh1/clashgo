package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"clashgo/internal/yaml"
)

// 分享链接订阅（常见的 vmess://... / vless://... 列表）不是 Clash YAML。
// Clash Party 会接收这类链接并自动转换，这里做同样处理，
// 让只提供分享链接的订阅也能正常导入。
//
// 转换器只生成当前内核已支持的字段；未知选项不写入 YAML，避免猜测。

type generatedProxy = map[string]any

type generatedConfig struct {
	Proxies     []generatedProxy `yaml:"proxies"`
	ProxyGroups []generatedProxy `yaml:"proxy-groups"`
	Rules       []string         `yaml:"rules"`
}

// ConvertShareLinks 把以换行分隔的代理分享链接转换成最小 Clash 配置。
// 没有找到任何受支持的链接时返回错误。
func ConvertShareLinks(raw []byte) ([]byte, error) {
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	var proxies []generatedProxy
	names := map[string]int{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, ok := parseShareLink(line)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		if name == "" {
			name = fmt.Sprintf("节点 %d", len(proxies)+1)
		}
		if n := names[name]; n > 0 {
			names[name] = n + 1
			name = fmt.Sprintf("%s (%d)", name, n+1)
		} else {
			names[name] = 1
		}
		p["name"] = name
		proxies = append(proxies, p)
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no supported share links found")
	}

	nodeNames := make([]string, 0, len(proxies))
	for _, p := range proxies {
		nodeNames = append(nodeNames, p["name"].(string))
	}
	cfg := generatedConfig{
		Proxies: proxies,
		ProxyGroups: []generatedProxy{
			{
				"name":    "PROXY",
				"type":    "select",
				"proxies": append([]string{"自动选择"}, nodeNames...),
			},
			{
				"name":    "自动选择",
				"type":    "url-test",
				"url":     "https://www.gstatic.com/generate_204",
				"proxies": nodeNames,
			},
		},
		// 默认规则：大陆域名/IP 直连、广告拒绝、其余走代理。
		// 分享链接订阅通常不带 rules，若不生成这些规则，所有流量（含
		// 大陆网站如 bilibili）都会走代理，导致大陆网站连不上。
		Rules: []string{
			"GEOSITE,category-ads-all,REJECT",
			"GEOSITE,private,DIRECT",
			"GEOSITE,geolocation-cn,DIRECT",
			"GEOIP,cn,DIRECT",
			"MATCH,PROXY",
		},
	}
	return yaml.Marshal(cfg)
}

func parseShareLink(line string) (generatedProxy, bool) {
	switch {
	case strings.HasPrefix(line, "vmess://"):
		return parseVMess(line)
	case strings.HasPrefix(line, "vless://"):
		return parseVLESS(line)
	case strings.HasPrefix(line, "trojan://"):
		return parseTrojan(line)
	case strings.HasPrefix(line, "ss://"):
		return parseShadowsocks(line)
	case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
		return parseHysteria2(line)
	case strings.HasPrefix(line, "tuic://"):
		return parseTUIC(line)
	default:
		return nil, false
	}
}

func b64decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

func parseVMess(line string) (generatedProxy, bool) {
	body := strings.TrimPrefix(line, "vmess://")
	raw, err := b64decode(body)
	if err != nil {
		return nil, false
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false
	}
	server := str(v["add"])
	port := intv(v["port"])
	uuid := str(v["id"])
	if server == "" || port == 0 || uuid == "" {
		return nil, false
	}
	p := generatedProxy{
		"name":    str(v["ps"]),
		"type":    "vmess",
		"server":  server,
		"port":    port,
		"uuid":    uuid,
		"alterId": intv(v["aid"]),
		"cipher":  firstNonEmpty(str(v["scy"]), "auto"),
	}
	network := firstNonEmpty(str(v["net"]), "tcp")
	p["network"] = network
	if tls := str(v["tls"]); tls != "" && tls != "none" {
		p["tls"] = true
		p["servername"] = firstNonEmpty(str(v["sni"]), str(v["host"]), server)
	}
	if host := str(v["host"]); host != "" {
		p["host"] = host
	}
	if path := str(v["path"]); path != "" {
		p["path"] = path
	}
	return p, true
}

func parseVLESS(line string) (generatedProxy, bool) {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil, false
	}
	server := u.Hostname()
	port := atoi(u.Port())
	uuid := u.User.Username()
	if server == "" || port == 0 || uuid == "" {
		return nil, false
	}
	q := u.Query()
	p := generatedProxy{
		"name":   fragmentName(u),
		"type":   "vless",
		"server": server,
		"port":   port,
		"uuid":   uuid,
	}
	// 保留 flow（含 Reality 的 xtls-rprx-vision）。
	// 我们用自研 internal/vision 在 Reality 明文层实现 Vision padding。
	if flow := q.Get("flow"); flow != "" {
		p["flow"] = flow
	}
	if typ := q.Get("type"); typ != "" {
		p["network"] = typ
	}
	if security := q.Get("security"); security == "tls" || security == "reality" {
		p["tls"] = true
		p["servername"] = firstNonEmpty(q.Get("sni"), q.Get("host"), server)
		if security == "reality" {
			opts := generatedProxy{}
			if pbk := q.Get("pbk"); pbk != "" {
				opts["public-key"] = pbk
			}
			if sid := q.Get("sid"); sid != "" {
				opts["short-id"] = sid
			}
			if len(opts) > 0 {
				p["reality-opts"] = opts
			}
		}
	}
	if host := q.Get("host"); host != "" {
		p["host"] = host
	}
	if path := q.Get("path"); path != "" {
		p["path"] = path
	}
	return p, true
}

func parseTrojan(line string) (generatedProxy, bool) {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil, false
	}
	server := u.Hostname()
	port := atoi(u.Port())
	password := u.User.Username()
	if server == "" || port == 0 || password == "" {
		return nil, false
	}
	q := u.Query()
	p := generatedProxy{
		"name":       fragmentName(u),
		"type":       "trojan",
		"server":     server,
		"port":       port,
		"password":   password,
		"tls":        true,
		"servername": firstNonEmpty(q.Get("sni"), q.Get("peer"), server),
	}
	if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
		p["skip-cert-verify"] = true
	}
	return p, true
}

func parseShadowsocks(line string) (generatedProxy, bool) {
	body := strings.TrimPrefix(line, "ss://")
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	query := ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		query = body[i+1:]
		body = body[:i]
	}
	var method, password, server string
	var port int
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		cred := body[:at]
		hostPort := body[at+1:]
		if dec, err := b64decode(cred); err == nil {
			cred = string(dec)
		}
		if i := strings.IndexByte(cred, ':'); i > 0 {
			method, password = cred[:i], cred[i+1:]
		}
		if h, p, err := splitHostPort(hostPort); err == nil {
			server, port = h, p
		}
	} else {
		dec, err := b64decode(body)
		if err != nil {
			return nil, false
		}
		plain := string(dec)
		if at := strings.LastIndexByte(plain, '@'); at >= 0 {
			cred, hostPort := plain[:at], plain[at+1:]
			if i := strings.IndexByte(cred, ':'); i > 0 {
				method, password = cred[:i], cred[i+1:]
			}
			if h, p, err := splitHostPort(hostPort); err == nil {
				server, port = h, p
			}
		}
	}
	if server == "" || port == 0 || method == "" {
		return nil, false
	}
	p := generatedProxy{
		"name": name, "type": "ss", "server": server, "port": port,
		"cipher": method, "password": password,
	}
	if query != "" {
		if q, err := url.ParseQuery(query); err == nil && (q.Get("plugin") != "" || q.Get("obfs") != "") {
			if plugin := q.Get("plugin"); plugin != "" {
				p["plugin"] = plugin
				p["plugin-opts"] = q.Get("plugin-opts")
			}
		}
	}
	return p, true
}

func parseHysteria2(line string) (generatedProxy, bool) {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil, false
	}
	server := u.Hostname()
	port := atoi(u.Port())
	password := u.User.Username()
	if server == "" || port == 0 {
		return nil, false
	}
	q := u.Query()
	p := generatedProxy{
		"name":     fragmentName(u),
		"type":     "hysteria2",
		"server":   server,
		"port":     port,
		"password": password,
	}
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer")); sni != "" {
		p["servername"] = sni
	}
	if q.Get("insecure") == "1" || q.Get("insecure") == "true" {
		p["skip-cert-verify"] = true
	}
	return p, true
}

func parseTUIC(line string) (generatedProxy, bool) {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil, false
	}
	server := u.Hostname()
	port := atoi(u.Port())
	if server == "" || port == 0 {
		return nil, false
	}
	q := u.Query()
	p := generatedProxy{
		"name":   fragmentName(u),
		"type":   "tuic",
		"server": server,
		"port":   port,
		"uuid":   u.User.Username(),
	}
	if token, ok := u.User.Password(); ok {
		p["token"] = token
	}
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer")); sni != "" {
		p["servername"] = sni
	}
	return p, true
}

func fragmentName(u *url.URL) string {
	if u.Fragment == "" {
		return ""
	}
	name, err := url.PathUnescape(u.Fragment)
	if err != nil {
		return u.Fragment
	}
	return name
}

func splitHostPort(s string) (string, int, error) {
	u, err := url.Parse("//" + s)
	if err != nil {
		return "", 0, err
	}
	return u.Hostname(), atoi(u.Port()), nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func intv(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		return atoi(x)
	case int:
		return x
	default:
		return 0
	}
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
