// Package autogroup generates proxy groups by matching node names against
// region patterns (idea from common practice). No network
// calls — it works purely from subscription node names.
package autogroup

import (
	"regexp"
	"sort"
	"strings"
)

// RegionPatterns maps a region code to a name-matching rule. Each entry is a
// list of substrings/regex-ish tokens; a node matches if it contains any.
var RegionPatterns = []struct {
	Code    string
	Name    string
	Pattern string // regular expression
}{
	{"JP", "日本", `日本|[Jj][Pp]\b|🇯🇵|[Jj]apan`},
	{"US", "美国", `美国|[Uu][Ss]\b|🇺🇸|[Uu]nited[ -][Ss]tates|\b[Uu][Ss][Aa]\b`},
	{"HK", "香港", `香港|[Hh][Kk]\b|🇭🇰|[Hh]ong[ -][Kk]ong`},
	{"TW", "台湾", `台湾|台灣|[Tt][Ww]\b|🇹🇼|[Tt]aiwan`},
	{"SG", "新加坡", `新加坡|[Ss][Gg]\b|🇸🇬|[Ss]ingapore`},
	{"KR", "韩国", `韩国|韓國|[Kk][Rr]\b|🇰🇷|[Kk]orea`},
	{"DE", "德国", `德国|德國|[Dd][Ee]\b|🇩🇪|[Gg]ermany`},
	{"GB", "英国", `英国|英國|[Gg][Bb]\b|🇬🇧|[Uu][Kk]\b|[Bb]ritain`},
	{"FR", "法国", `法国|法國|[Ff][Rr]\b|🇫🇷|[Ff]rance`},
	{"CA", "加拿大", `加拿大|[Cc][Aa]\b|🇨🇦|[Cc]anada`},
	{"AU", "澳大利亚", `澳大利亚|澳洲|[Aa][Uu]\b|🇦🇺|[Aa]ustralia`},
	{"RU", "俄罗斯", `俄罗斯|俄羅斯|[Rr][Uu]\b|🇷🇺|[Rr]ussia`},
	{"IN", "印度", `印度|[Ii][Nn]\b|🇮🇳|[Ii]ndia`},
	{"BR", "巴西", `巴西|[Bb][Rr]\b|🇧🇷|[Bb]razil`},
	{"VN", "越南", `越南|[Vv][Nn]\b|🇻🇳|[Vv]ietnam`},
	{"ID", "印尼", `印尼|印度尼西亚|[Ii][Dd]\b|🇮🇩|[Ii]ndonesia`},
	{"MX", "墨西哥", `墨西哥|[Mm][Xx]\b|🇲🇽|[Mm]exico`},
}

// excludeRe filters out nodes whose names carry traffic/expiry metadata.
var excludeRe = regexp.MustCompile(`剩余|过期|到期|重置|[Rr]emaining|[Ee]xpir|[Rr]eset`)

// Group is a generated proxy group.
type Group struct {
	Code    string
	Name    string
	Members []string
}

// Build groups nodes into region groups. nodes is the full node-name list;
// the returned groups only contain non-empty matches, sorted by member count.
func Build(nodes []string) []Group {
	type compiled struct {
		code, name string
		re         *regexp.Regexp
	}
	var cs []compiled
	for _, rp := range RegionPatterns {
		re, err := regexp.Compile(rp.Pattern)
		if err != nil {
			continue
		}
		cs = append(cs, compiled{rp.Code, rp.Name, re})
	}
	var groups []Group
	for _, c := range cs {
		var members []string
		for _, n := range nodes {
			if excludeRe.MatchString(n) {
				continue
			}
			if c.re.MatchString(n) {
				members = append(members, n)
			}
		}
		if len(members) > 0 {
			groups = append(groups, Group{Code: c.code, Name: c.name, Members: members})
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if len(groups[i].Members) == len(groups[j].Members) {
			return groups[i].Code < groups[j].Code
		}
		return len(groups[i].Members) > len(groups[j].Members)
	})
	return groups
}

// GroupName returns the 自研内核 group name for a region group.
func GroupName(g Group) string {
	return "🌍 " + g.Name + " " + strings.ToUpper(g.Code)
}

// RegionOf 返回节点名对应的地区名（如「香港」），无法识别时返回空串。
//
// 纯名称匹配，不发网络请求。用于界面上的轻量地区标签。
func RegionOf(node string) string {
	if node == "" || excludeRe.MatchString(node) {
		return ""
	}
	for _, rp := range RegionPatterns {
		re, err := regexp.Compile(rp.Pattern)
		if err != nil {
			continue
		}
		if re.MatchString(node) {
			return rp.Name
		}
	}
	return ""
}
