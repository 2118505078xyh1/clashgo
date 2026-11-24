package minikernel

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"clashgo/internal/ruleindex"
)

type baseRule struct {
	typ, payload, adapter string
}

func (r *baseRule) Type() string    { return r.typ }
func (r *baseRule) Payload() string { return r.payload }
func (r *baseRule) Adapter() string { return r.adapter }

// domainRule 精确域名匹配（payload 预转小写）。
type domainRule struct {
	baseRule
	lower string
}

func (r *domainRule) Match(m *Metadata) (bool, string) {
	return m.RuleHost() == r.lower, r.adapter
}

// domainSuffixRule 域名后缀匹配（payload 预转小写 + 预加前导点）。
type domainSuffixRule struct {
	baseRule
	lower   string
	withDot string
}

func (r *domainSuffixRule) Match(m *Metadata) (bool, string) {
	domain := m.RuleHost()
	return domain == r.lower || strings.HasSuffix(domain, r.withDot), r.adapter
}

// domainKeywordRule 域名关键字匹配（payload 预转小写）。
type domainKeywordRule struct {
	baseRule
	lower string
}

func (r *domainKeywordRule) Match(m *Metadata) (bool, string) {
	return strings.Contains(m.RuleHost(), r.lower), r.adapter
}

type ipcidrRule struct {
	baseRule
	prefix    netip.Prefix
	noResolve bool // no-resolve 参数：域名连接不触发 DNS 解析
}

func (r *ipcidrRule) Match(m *Metadata) (bool, string) {
	ip := m.DstIP
	if !ip.IsValid() && !r.noResolve && m.ResolveIP != nil {
		ip = m.ResolveIP() // 惰性解析：只有走到 IP 规则才查询
	}
	return ip.IsValid() && r.prefix.Contains(ip), r.adapter
}

type matchRule struct{ baseRule }

func (r *matchRule) Match(m *Metadata) (bool, string) { return true, r.adapter }

// portRule 目标/源端口规则（DST-PORT / SRC-PORT）。
type portRule struct {
	baseRule
	ports map[uint16]bool
	src   bool
}

func (r *portRule) Match(m *Metadata) (bool, string) {
	p := m.DstPort
	if r.src {
		p = m.SrcPort
	}
	return r.ports[p], r.adapter
}

// networkRule 网络类型规则（NETWORK: tcp/udp）。
type networkRule struct {
	baseRule
	network string
}

func (r *networkRule) Match(m *Metadata) (bool, string) {
	return strings.EqualFold(m.Network, r.network), r.adapter
}

// inTypeRule 入站类型规则（IN-TYPE: socks5/http/tun）。
type inTypeRule struct {
	baseRule
	inType string
}

func (r *inTypeRule) Match(m *Metadata) (bool, string) {
	return strings.EqualFold(m.Type, r.inType), r.adapter
}

// processRule 进程名规则（PROCESS-NAME）。
type processRule struct {
	baseRule
	name string
}

func (r *processRule) Match(m *Metadata) (bool, string) {
	return m.Process != "" && strings.EqualFold(m.Process, r.name), r.adapter
}

// ruleSetRule 引用命名规则集（RULE-SET）。
type ruleSetRule struct {
	baseRule
	setName string
}

func (r *ruleSetRule) Match(m *Metadata) (bool, string) {
	if set, ok := ruleSets[r.setName]; ok {
		if matched, _ := set.Match(m); matched {
			return true, r.adapter
		}
		return false, r.adapter
	}
	return false, r.adapter
}

// ruleSets 全局规则集注册表（配置加载时填充）。
var ruleSets = map[string]*ruleSetHolder{}

// ruleSetHolder 用一个复合规则表示规则集（域名/IP 用 OR 语义）。
type ruleSetHolder struct {
	domainRules []Rule
	ipRules     []Rule
}

func (h *ruleSetHolder) Type() string    { return "RULE-SET" }
func (h *ruleSetHolder) Payload() string { return "" }
func (h *ruleSetHolder) Adapter() string { return "" }
func (h *ruleSetHolder) Match(m *Metadata) (bool, string) {
	for _, r := range h.domainRules {
		if ok, a := r.Match(m); ok {
			return true, a
		}
	}
	for _, r := range h.ipRules {
		if ok, a := r.Match(m); ok {
			return true, a
		}
	}
	return false, ""
}

// geoipRule 基于内置国家 IP 段的 GEOIP 规则。
type geoipRule struct {
	baseRule
	prefixes []netip.Prefix
}

func (r *geoipRule) Match(m *Metadata) (bool, string) {
	ip := m.DstIP
	if !ip.IsValid() && m.ResolveIP != nil {
		ip = m.ResolveIP()
	}
	if !ip.IsValid() {
		return false, r.adapter
	}
	for _, p := range r.prefixes {
		if p.Contains(ip) {
			return true, r.adapter
		}
	}
	return false, r.adapter
}

// geositeRule 基于内置域名分类的 GEOSITE 规则。
type geositeRule struct {
	baseRule
	domains  map[string]bool // 精确域名
	suffixes []string        // 后缀
}

func (r *geositeRule) Match(m *Metadata) (bool, string) {
	host := m.RuleHost()
	if host == "" {
		return false, r.adapter
	}
	if r.domains[host] {
		return true, r.adapter
	}
	for _, s := range r.suffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true, r.adapter
		}
	}
	return false, r.adapter
}

// geoIPData 内置国家 IP 段（精简，覆盖中国大陆主要网段）。
var geoIPData = map[string][]string{
	"cn": {
		"1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/21", "1.0.32.0/19", "1.1.0.0/24",
		"1.2.4.0/24", "1.2.8.0/21", "1.3.0.0/16", "14.0.0.0/8", "27.0.0.0/8",
		"36.0.0.0/8", "39.0.0.0/8", "42.0.0.0/8", "43.0.0.0/8", "49.0.0.0/8",
		"58.0.0.0/8", "59.0.0.0/8", "60.0.0.0/8", "61.0.0.0/8", "101.0.0.0/8",
		"103.0.0.0/8", "106.0.0.0/8", "110.0.0.0/8", "111.0.0.0/8", "112.0.0.0/8",
		"113.0.0.0/8", "114.0.0.0/8", "115.0.0.0/8", "116.0.0.0/8", "117.0.0.0/8",
		"118.0.0.0/8", "119.0.0.0/8", "120.0.0.0/8", "121.0.0.0/8", "122.0.0.0/8",
		"123.0.0.0/8", "124.0.0.0/8", "125.0.0.0/8", "182.0.0.0/8", "183.0.0.0/8",
		"211.0.0.0/8", "212.0.0.0/8", "218.0.0.0/8", "219.0.0.0/8", "220.0.0.0/8",
		"221.0.0.0/8", "222.0.0.0/8", "223.0.0.0/8",
	},
}

// geoSiteData 内置域名分类（精简，覆盖常见国内/广告域名）。
var geoSiteData = map[string][]string{
	"geolocation-!cn":  {"google.com", "youtube.com", "facebook.com", "twitter.com", "github.com", "openai.com"},
	"geolocation-cn":   {"baidu.com", "qq.com", "taobao.com", "jd.com", "bilibili.com", "163.com", "weibo.com", "aliyun.com", "cn"},
	"category-ads-all": {"doubleclick.net", "googleadservices.com", "ads.youtube.com", "adservice.google.com"},
}

// ParseRule 解析一条 Clash 风格规则："DOMAIN-SUFFIX,google.com,DIRECT"。
// 支持 DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / IP-CIDR6 / MATCH。
func ParseRule(line string) (Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("empty rule")
	}
	parts := strings.Split(line, ",")
	typ := strings.ToUpper(strings.TrimSpace(parts[0]))
	// MATCH 常写成 "MATCH,DIRECT"（无 payload）；其它规则需要 type,payload,adapter。
	if typ == "MATCH" {
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid rule %q", line)
		}
		return &matchRule{baseRule{typ: typ, adapter: strings.ToUpper(strings.TrimSpace(parts[len(parts)-1]))}}, nil
	}
	if typ == "RULE-SET" {
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid rule %q", line)
		}
		return &ruleSetRule{baseRule: baseRule{typ: typ, payload: strings.TrimSpace(parts[1]), adapter: strings.ToUpper(strings.TrimSpace(parts[2]))}, setName: strings.ToLower(strings.TrimSpace(parts[1]))}, nil
	}
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid rule %q: need type,payload,adapter", line)
	}
	payload := strings.TrimSpace(parts[1])
	adapter := strings.ToUpper(strings.TrimSpace(parts[2]))
	base := baseRule{typ: typ, payload: payload, adapter: adapter}

	switch typ {
	case "DOMAIN":
		return &domainRule{baseRule: base, lower: strings.ToLower(payload)}, nil
	case "DOMAIN-SUFFIX":
		lower := strings.ToLower(payload)
		return &domainSuffixRule{baseRule: base, lower: lower, withDot: "." + lower}, nil
	case "DOMAIN-KEYWORD":
		return &domainKeywordRule{baseRule: base, lower: strings.ToLower(payload)}, nil
	case "DST-PORT", "SRC-PORT":
		ports := map[uint16]bool{}
		for _, ps := range strings.Split(payload, ";") {
			if n, err := strconv.Atoi(strings.TrimSpace(ps)); err == nil && n >= 0 && n <= 65535 {
				ports[uint16(n)] = true
			}
		}
		return &portRule{baseRule: base, ports: ports, src: typ == "SRC-PORT"}, nil
	case "NETWORK":
		return &networkRule{baseRule: base, network: strings.ToLower(payload)}, nil
	case "IN-TYPE":
		return &inTypeRule{baseRule: base, inType: strings.ToLower(payload)}, nil
	case "PROCESS-NAME":
		return &processRule{baseRule: base, name: strings.ToLower(payload)}, nil
	case "GEOIP":
		country := strings.ToLower(payload)
		// 优先用 ruleindex 的完整 GeoIP 数据库（CN 471 段等），回退到内置精简列表。
		prefixes := ruleindex.GeoIPCidrs(country)
		if len(prefixes) == 0 {
			pps, ok := geoIPData[country]
			if !ok {
				return nil, fmt.Errorf("unknown geoip country %q", payload)
			}
			for _, s := range pps {
				if p, err := netip.ParsePrefix(s); err == nil {
					prefixes = append(prefixes, p.Masked())
				}
			}
		}
		return &geoipRule{baseRule: base, prefixes: prefixes}, nil
	case "GEOSITE":
		domains := ruleindex.GeoSiteDomains(payload)
		if len(domains) == 0 {
			var ok bool
			domains, ok = geoSiteData[strings.ToLower(payload)]
			if !ok {
				return nil, fmt.Errorf("unknown geosite category %q", payload)
			}
		}
		r := &geositeRule{baseRule: base, domains: map[string]bool{}, suffixes: []string{}}
		for _, d := range domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if strings.HasPrefix(d, ".") {
				r.suffixes = append(r.suffixes, strings.TrimPrefix(d, "."))
			} else {
				// 静态表里的域名（如 bilibili.com）应匹配自身及所有子域。
				// 只放 domains 会导致 www.bilibili.com 无法命中。
				r.domains[d] = true
				r.suffixes = append(r.suffixes, d)
			}
		}
		return r, nil
	case "IP-CIDR", "IP-CIDR6":
		p, err := netip.ParsePrefix(payload)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", payload, err)
		}
		noResolve := false
		for _, param := range parts[3:] {
			if strings.EqualFold(strings.TrimSpace(param), "no-resolve") {
				noResolve = true
			}
		}
		return &ipcidrRule{baseRule: base, prefix: p.Masked(), noResolve: noResolve}, nil
	default:
		return nil, fmt.Errorf("unsupported rule type %q", typ)
	}
}

// AddRules 批量添加规则（跳过非法行，返回成功数）。
func (k *Kernel) AddRules(lines []string) int {
	added := 0
	for _, line := range lines {
		r, err := ParseRule(line)
		if err != nil {
			continue
		}
		k.Rules = append(k.Rules, r)
		added++
	}
	if added > 0 {
		k.publishSnapshot() // 规则变更后发布新快照（热重载）
	}
	return added
}
