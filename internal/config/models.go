// Package config defines the data models persisted to settings.yaml and
// profiles.yaml, mirroring the models used by a reference GUI.
package config

// Settings is the application's own configuration (equivalent of verge.yaml).
type Settings struct {
	// Appearance
	ThemeMode       string `yaml:"theme-mode" json:"theme-mode"`       // system | light | dark
	PrimaryColor    string `yaml:"primary-color" json:"primary-color"` // hex, e.g. #5b8cff
	UseSystemAccent bool   `yaml:"use-system-accent" json:"use-system-accent"`
	Language        string `yaml:"language" json:"language"`
	StartPage       string `yaml:"start-page" json:"start-page"`

	// Ports
	MixedPort          int    `yaml:"mixed-port" json:"mixed-port"`
	SocksPort          int    `yaml:"socks-port" json:"socks-port"`
	HTTPPort           int    `yaml:"http-port" json:"http-port"`
	SocksEnabled       bool   `yaml:"socks-enabled" json:"socks-enabled"`
	HTTPEnabled        bool   `yaml:"http-enabled" json:"http-enabled"`
	EnableLightweight  bool   `yaml:"enable-lightweight" json:"enable-lightweight"`
	LightweightMinutes int    `yaml:"lightweight-minutes" json:"lightweight-minutes"`
	ExternalController string `yaml:"external-controller" json:"external-controller"`
	Secret             string `yaml:"secret" json:"secret"`
	Mode               string `yaml:"mode" json:"mode"` // rule | direct | global
	LogLevel           string `yaml:"log-level" json:"log-level"`

	// System proxy
	EnableSystemProxy bool   `yaml:"enable-system-proxy" json:"enable-system-proxy"`
	ProxyBypass       string `yaml:"proxy-bypass" json:"proxy-bypass"`
	EnableProxyGuard  bool   `yaml:"enable-proxy-guard" json:"enable-proxy-guard"`

	// TUN
	EnableTUN         bool   `yaml:"enable-tun" json:"enable-tun"`
	TUNStack          string `yaml:"tun-stack" json:"tun-stack"` // gvisor | system | mixed
	TUNAutoRoute      bool   `yaml:"tun-auto-route" json:"tun-auto-route"`
	EnableDNSOverride bool   `yaml:"enable-dns-override" json:"enable-dns-override"`
	Nameserver        string `yaml:"nameserver" json:"nameserver"`
	EnableSSIDRule    bool   `yaml:"enable-ssid-rule" json:"enable-ssid-rule"`
	SSIDAllowlist     string `yaml:"ssid-allowlist" json:"ssid-allowlist"`

	// Startup
	AutoLaunch  bool `yaml:"auto-launch" json:"auto-launch"`
	SilentStart bool `yaml:"silent-start" json:"silent-start"`

	// 内核后端：self = 进程内自研内核；mihomo = 外部 mihomo 核心。
	// mihomo 后端在 Reality / XTLS Vision 等细节上更成熟。
	CoreBackend string `yaml:"core-backend" json:"core-backend"`

	// PAC
	EnablePAC       bool   `yaml:"enable-pac" json:"enable-pac"`
	EnablePACSystem bool   `yaml:"enable-pac-system" json:"enable-pac-system"`
	PACContent      string `yaml:"pac-content,omitempty" json:"pac-content,omitempty"`

	// WebDAV
	WebDAVURL      string `yaml:"webdav-url,omitempty" json:"webdav-url,omitempty"`
	WebDAVUsername string `yaml:"webdav-username,omitempty" json:"webdav-username,omitempty"`
	WebDAVPassword string `yaml:"webdav-password,omitempty" json:"webdav-password,omitempty"`

	// Hotkeys
	EnableHotkeys bool   `yaml:"enable-hotkeys" json:"enable-hotkeys"`
	HotkeyToggle  string `yaml:"hotkey-toggle" json:"hotkey-toggle"`
	HotkeyShow    string `yaml:"hotkey-show" json:"hotkey-show"`

	// Behavior
	AutoCheckUpdate bool   `yaml:"auto-check-update" json:"auto-check-update"`
	LatencyTestURL  string `yaml:"latency-test-url" json:"latency-test-url"`
	LatencyTimeout  int    `yaml:"latency-timeout" json:"latency-timeout"`

	// Security
	SafeMode       bool   `yaml:"safe-mode" json:"safe-mode"` // harden the runtime config at startup
	ReadOnly       bool   `yaml:"read-only" json:"read-only"` // reject every mutating operation
	WebAPIEnabled  bool   `yaml:"web-api-enabled" json:"web-api-enabled"`
	WebAPIPort     int    `yaml:"web-api-port" json:"web-api-port"`
	WebAPISecret   string `yaml:"web-api-secret" json:"web-api-secret"`
	OnboardingDone bool   `yaml:"onboarding-done" json:"onboarding-done"`
}

// DefaultSettings returns sane defaults close to a reference GUI.
func DefaultSettings() *Settings {
	return &Settings{
		ThemeMode:          "dark",
		PrimaryColor:       "#5b8cff",
		UseSystemAccent:    true,
		Language:           "zh",
		StartPage:          "/home",
		MixedPort:          7897,
		SocksPort:          7898,
		HTTPPort:           7899,
		SocksEnabled:       true,
		HTTPEnabled:        true,
		LightweightMinutes: 10,
		ExternalController: "127.0.0.1:9097",
		Secret:             "clashgo",
		Mode:               "rule",
		LogLevel:           "info",
		CoreBackend:        "mihomo",
		ProxyBypass:        "localhost,127.0.0.1,::1,*.local,*.arpa,<local>",
		TUNStack:           "gvisor",
		TUNAutoRoute:       true,
		Nameserver:         "223.5.5.5,119.29.29.29",
		LatencyTestURL:     "https://www.gstatic.com/generate_204",
		LatencyTimeout:     5000,
		AutoCheckUpdate:    true,
		WebAPIPort:         9099,
		EnableHotkeys:      false,
		HotkeyToggle:       "CmdOrCtrl+Shift+S",
		HotkeyShow:         "CmdOrCtrl+Shift+D",
	}
}

// ProfileType distinguishes the kind of profile entry.
type ProfileType string

const (
	ProfileLocal       ProfileType = "local"
	ProfileRemote      ProfileType = "remote"
	ProfileMerge       ProfileType = "merge"
	ProfileScript      ProfileType = "script"
	ProfileRules       ProfileType = "rules"
	ProfileProxies     ProfileType = "proxies"
	ProfileGroups      ProfileType = "groups"
	ProfileComposition ProfileType = "composition"
)

// PrfOption holds per-profile behavior options.
type PrfOption struct {
	UserAgent       string `yaml:"user-agent,omitempty" json:"user-agent,omitempty"`
	WithProxy       bool   `yaml:"with-proxy,omitempty" json:"with-proxy,omitempty"`
	UpdateInterval  int    `yaml:"update-interval,omitempty" json:"update-interval,omitempty"` // minutes, 0 = manual
	TimeoutSeconds  int    `yaml:"timeout-seconds,omitempty" json:"timeout-seconds,omitempty"`
	AllowAutoUpdate bool   `yaml:"allow-auto-update,omitempty" json:"allow-auto-update,omitempty"`
	// Subscription conversion service base URL (a subscription conversion service).
	// When set, the source URL is passed to it for conversion to Clash YAML.
	ConvertTarget string `yaml:"convert-target,omitempty" json:"convert-target,omitempty"`
	// Fallback URL used when the primary source fails.
	MoreURL string `yaml:"more-url,omitempty" json:"more-url,omitempty"`
	// Enhancement attachment UIDs (reference other PrfItems by UID).
	Merge   string `yaml:"merge,omitempty" json:"merge,omitempty"`
	Script  string `yaml:"script,omitempty" json:"script,omitempty"`
	Rules   string `yaml:"rules,omitempty" json:"rules,omitempty"`
	Proxies string `yaml:"proxies,omitempty" json:"proxies,omitempty"`
	Groups  string `yaml:"groups,omitempty" json:"groups,omitempty"`

	// Subscription-level chained proxy (chained-proxy style).
	// PrevProfile/NextProfile reference other PrfItems by UID and form a chain
	// "prev -> this -> next". PreSocksPort is the local SOCKS port exposed by
	// the preceding hop so this profile can route through it.
	PreSocksPort int    `yaml:"pre-socks-port,omitempty" json:"pre-socks-port,omitempty"`
	PrevProfile  string `yaml:"prev-profile,omitempty" json:"prev-profile,omitempty"`
	NextProfile  string `yaml:"next-profile,omitempty" json:"next-profile,omitempty"`
}

// ProfileTraffic records subscription traffic statistics.
type ProfileTraffic struct {
	Upload   int64 `yaml:"upload" json:"upload"`
	Download int64 `yaml:"download" json:"download"`
	Total    int64 `yaml:"total" json:"total"`
	Expire   int64 `yaml:"expire" json:"expire"`
}

// CompositionSpec declares a "node pool" profile that merges proxies from
// multiple subscriptions (base + contributors), inspired by common practice.
type CompositionSpec struct {
	Base         string   `yaml:"base,omitempty" json:"base,omitempty"`
	Contributors []string `yaml:"extend_proxies_from,omitempty" json:"extend-proxies-from,omitempty"`
}

// PrfItem is one entry in profiles.yaml.
type PrfItem struct {
	UID         string            `yaml:"uid" json:"uid"`
	Type        ProfileType       `yaml:"type" json:"type"`
	Name        string            `yaml:"name" json:"name"`
	File        string            `yaml:"file" json:"file"` // filename under profiles/
	Desc        string            `yaml:"desc,omitempty" json:"desc,omitempty"`
	URL         string            `yaml:"url,omitempty" json:"url,omitempty"`
	Selected    map[string]string `yaml:"selected,omitempty" json:"selected,omitempty"` // group -> chosen node
	Extra       *ProfileTraffic   `yaml:"extra,omitempty" json:"extra,omitempty"`
	Updated     int64             `yaml:"updated,omitempty" json:"updated,omitempty"`
	Option      *PrfOption        `yaml:"option,omitempty" json:"option,omitempty"`
	Composition *CompositionSpec  `yaml:"composition,omitempty" json:"composition,omitempty"`
}

// ProfilesDB is the content of profiles.yaml.
type ProfilesDB struct {
	Current string     `yaml:"current,omitempty" json:"current,omitempty"`
	Items   []*PrfItem `yaml:"items,omitempty" json:"items,omitempty"`
}

// Find returns the profile with the given uid.
func (p *ProfilesDB) Find(uid string) *PrfItem {
	for _, item := range p.Items {
		if item.UID == uid {
			return item
		}
	}
	return nil
}

// CurrentItem returns the currently selected profile.
func (p *ProfilesDB) CurrentItem() *PrfItem {
	return p.Find(p.Current)
}

// ProxyView is a simplified, UI-friendly representation of 自研内核's proxies.
type ProxyView struct {
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Now     string         `json:"now"`
	All     []string       `json:"all"`
	History []DelayHistory `json:"history"`
	UDP     bool           `json:"udp"`
	Group   bool           `json:"group"`
}

// DelayHistory is one latency measurement.
type DelayHistory struct {
	Time  string `json:"time"`
	Delay int    `json:"delay"`
}

// ConnectionView is a simplified representation of an active connection.
type ConnectionView struct {
	ID            string   `json:"id"`
	Start         string   `json:"start"`
	Host          string   `json:"host"`
	Full          string   `json:"full"`
	Network       string   `json:"network"`
	Type          string   `json:"type"`
	Rule          string   `json:"rule"`
	RulePayload   string   `json:"rulePayload"`
	Chain         []string `json:"chain"`
	Upload        int64    `json:"upload"`
	Download      int64    `json:"download"`
	SourceIP      string   `json:"sourceIP"`
	Process       string   `json:"process"`
	DestinationIP string   `json:"destinationIP"`
}

// LogView is one log line from the core.
type LogView struct {
	Type    string `json:"type"`
	Time    string `json:"time"`
	Payload string `json:"payload"`
}
