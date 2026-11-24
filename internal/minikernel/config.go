package minikernel

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"clashgo/internal/reality"
	"clashgo/internal/ssrproto"
	"clashgo/internal/wgproto"
	"clashgo/internal/yaml"
)

// ProxyConfig 是一个出站节点配置（当前支持 ss 类型）。
type ProxyConfig struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Cipher   string `yaml:"cipher"`
	Password string `yaml:"password"`

	// VMess 字段。
	UUID       string `yaml:"uuid"`
	AlterID    int    `yaml:"alterId"`
	Network    string `yaml:"network"`
	TLS        bool   `yaml:"tls"`
	ServerName string `yaml:"servername"`
	Path       string `yaml:"path"`
	Host       string `yaml:"host"`
	SkipCert   bool   `yaml:"skip-cert-verify"`
	Flow       string `yaml:"flow"`

	// Reality 字段（VLESS-Reality 使用）。
	RealityOpts *RealityOptions `yaml:"reality-opts,omitempty"`

	// Hysteria2 / TUIC 字段。
	Token     string `yaml:"token"`
	Bandwidth int    `yaml:"bandwidth"`
	// WireGuard 字段。
	PrivateKey    string   `yaml:"private-key"`
	PeerPublicKey string   `yaml:"peer-public-key"`
	AllowedIPs    []string `yaml:"allowed-ips"`
	Keepalive     int      `yaml:"persistent-keepalive"`
	// SSR 字段。
	Protocol      string `yaml:"protocol"`
	ProtocolParam string `yaml:"protocol-param"`
	Obfs          string `yaml:"obfs"`
	ObfsParam     string `yaml:"obfs-param"`
}

// RealityOptions 是 Reality 握手所需的认证参数。
type RealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

// Config 是内核的可解析配置。
type Config struct {
	DNS           DNSConfig                     `yaml:"dns"`
	TUN           TUNConfig                     `yaml:"tun"`
	Port          int                           `yaml:"port"`
	SocksPort     int                           `yaml:"socks-port"`
	MixedPort     int                           `yaml:"mixed-port"`
	Rules         []string                      `yaml:"rules"`
	Proxies       []ProxyConfig                 `yaml:"proxies"`
	ProxyGroups   []ProxyGroupConfig            `yaml:"proxy-groups"`
	RuleProviders map[string]RuleProviderConfig `yaml:"rule-providers"`
}

// ProxyGroupConfig 是一个代理组配置（selector / url-test）。
type ProxyGroupConfig struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
	URL     string   `yaml:"url"`
}

// LoadConfig 从 YAML 文件加载配置。
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfigBytes(b)
}

// ParseConfigBytes 从 YAML 字节解析配置（供 App 传入运行时生成的配置）。
func ParseConfigBytes(b []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// MixedAddr 返回 mixed 监听地址（优先 mixed-port）。
func (c *Config) MixedAddr() string {
	port := c.MixedPort
	if port == 0 {
		port = c.Port
	}
	if port == 0 {
		port = 7890
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

// NewKernelFromConfig 用配置构造内核：加载 ss 节点与规则。
func NewKernelFromConfig(c *Config) (*Kernel, error) {
	k := NewKernel()
	// 自动把所有节点服务器 IP 加入 TUN 排除列表，防止路由环路。
	for _, p := range c.Proxies {
		if ip, err := netip.ParseAddr(p.Server); err == nil && ip.Is4() {
			c.TUN.Exclude = append(c.TUN.Exclude, ip.String()+"/32")
		}
	}
	for _, p := range c.Proxies {
		server := net.JoinHostPort(p.Server, fmt.Sprint(p.Port))
		switch strings.ToLower(p.Type) {
		case "ss":
			out, err := NewShadowSocks(p.Name, server, p.Cipher, p.Password)
			if err != nil {
				return nil, fmt.Errorf("proxy %q: %w", p.Name, err)
			}
			k.Proxies[p.Name] = out
		case "ssr":
			ssrCfg := ssrproto.Config{
				Method: p.Cipher, Password: p.Password,
				Protocol: p.Protocol, ProtocolParam: p.ProtocolParam,
				Obfs: p.Obfs, ObfsParam: p.ObfsParam,
			}
			k.Proxies[p.Name] = newSSR(p.Name, server, ssrCfg)
		case "vmess":
			out, err := NewVMess(p.Name, server, p.UUID, p.Cipher, p.AlterID,
				p.Network, p.TLS, p.ServerName, p.Path, p.Host, p.SkipCert)
			if err != nil {
				return nil, fmt.Errorf("proxy %q: %w", p.Name, err)
			}
			k.Proxies[p.Name] = out
		case "vless":
			var realityCfg *reality.Config
			if p.RealityOpts != nil && p.RealityOpts.PublicKey != "" {
				realityCfg = &reality.Config{
					ServerName: p.ServerName,
					PublicKey:  p.RealityOpts.PublicKey,
					ShortID:    p.RealityOpts.ShortID,
					Flow:       p.Flow,
				}
			}
			out, err := NewVLESS(p.Name, server, p.UUID, p.Flow, p.Network,
				p.TLS, p.ServerName, p.Path, p.Host, p.SkipCert, realityCfg)
			if err != nil {
				return nil, fmt.Errorf("proxy %q: %w", p.Name, err)
			}
			k.Proxies[p.Name] = out
		case "trojan":
			k.Proxies[p.Name] = NewTrojan(p.Name, server, p.Password, p.TLS, p.ServerName, p.SkipCert)
		case "hysteria2":
			k.Proxies[p.Name] = newHysteria2Real(p.Name, server, p.Password, p.ServerName, p.SkipCert, p.Bandwidth)
		case "tuic":
			k.Proxies[p.Name] = newTUICReal(p.Name, server, p.UUID, p.Token, p.ServerName, p.SkipCert)
		case "wireguard":
			wgCfg := wgproto.Config{
				PrivateKey: p.PrivateKey, PeerPublicKey: p.PeerPublicKey,
				Endpoint: server, AllowedIPs: p.AllowedIPs, Keepalive: p.Keepalive,
			}
			k.Proxies[p.Name] = newWireGuard(p.Name, wgCfg)
		}
	}
	for _, g := range c.ProxyGroups {
		switch strings.ToLower(g.Type) {
		case "select":
			k.Proxies[g.Name] = NewSelector(k, g.Name, g.Proxies)
		case "url-test":
			k.Proxies[g.Name] = NewURLTest(k, g.Name, g.Proxies)
		case "fallback":
			k.Proxies[g.Name] = NewFallback(k, g.Name, g.Proxies)
		case "load-balance":
			k.Proxies[g.Name] = NewLoadBalance(k, g.Name, g.Proxies)
		}
	}
	k.AddRules(c.Rules)
	loadRuleProviders(c.RuleProviders)
	if c.DNS.Enable {
		if dnsSrv, err := startDNS(k, c.DNS); err == nil {
			k.DNS = dnsSrv
		}
	}
	if c.TUN.Enable {
		if srv, err := startTUN(k, c.TUN); err == nil {
			k.TUN = srv
		}
	}
	k.publishSnapshot() // 发布运行快照（热重载基础）
	return k, nil
}
