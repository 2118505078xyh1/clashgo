package enhance

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Include-all directive keys understood by 自研内核's ParseProxyGroup. The
// kernel does not expand them itself: it expects the parser to have already
// turned them into explicit `proxies` / `use` lists (AllProxies / AllProviders
// are built and sorted in config.parseProxies). This file mirrors common practice.rs so the config we hand to hub.ApplyConfig is already expanded.
const (
	keyIncludeAll          = "include-all"
	keyIncludeAllProxies   = "include-all-proxies"
	keyIncludeAllProviders = "include-all-providers"
	includeAllLogKey       = "include-all"
	defaultEmptyFallback   = "COMPATIBLE"
)

// ApplyIncludeAll scans every proxy-group and expands the include-all family
// of directives using the config's full, lexicographically sorted proxy and
// proxy-provider name lists. The three directive keys are removed afterwards.
//
// It must run before finalize()/cleanupGroups() so that the freshly injected
// references survive the "remove missing proxies" pass.
func ApplyIncludeAll(cfg Mapping, logs map[string][]string) {
	if cfg == nil {
		return
	}
	groups := toSlice(cfg["proxy-groups"])
	if len(groups) == 0 {
		return
	}

	// 自研内核: AllProxies = names from the `proxies` list, AllProviders = keys
	// of the `proxy-providers` mapping; both are sorted before use.
	allProxies := proxyNames(cfg["proxies"])
	sort.Strings(allProxies)
	allProviders := providerNames(cfg["proxy-providers"])
	sort.Strings(allProviders)

	for _, g := range groups {
		gm, ok := g.(Mapping)
		if !ok {
			continue
		}

		incAll, ok1 := weakBool(gm[keyIncludeAll])
		incProxies, ok2 := weakBool(gm[keyIncludeAllProxies])
		incProviders, ok3 := weakBool(gm[keyIncludeAllProviders])
		if !ok1 || !ok2 || !ok3 {
			logIncludeAll(logs, fmt.Sprintf("策略组 %q 的 include-all 字段类型无效，保留原样交给内核", itemName(gm)))
			continue
		}
		includeProxies := incProxies || incAll
		includeProviders := incProviders || incAll
		if !includeProxies && !includeProviders {
			continue
		}
		name, _ := gm["name"].(string)
		if name == "" {
			// The core rejects such a group anyway; leave it for the core to report.
			continue
		}

		proxies := toSlice(gm["proxies"])
		uses := toSlice(gm["use"])

		if includeProviders {
			uses = make([]any, 0, len(allProviders))
			for _, provider := range allProviders {
				uses = append(uses, provider)
			}
		}
		if includeProxies {
			filter, valid := weakString(gm["filter"])
			if !valid {
				logIncludeAll(logs, fmt.Sprintf("策略组 %q 的 filter 不是字符串，include-all 保留原样", name))
				continue
			}
			var expanded []any
			if filter == "" {
				for _, proxy := range allProxies {
					expanded = append(expanded, proxy)
				}
			} else {
				regs, err := compileFilters(filter)
				if err != nil {
					logIncludeAll(logs, fmt.Sprintf("策略组 %q 的 filter %q 无效：%v，include-all 保留原样", name, filter, err))
					continue
				}
				// Same loop shape as 自研内核: a proxy matching several filters is
				// appended once per match; dedup happens below.
				for _, proxy := range allProxies {
					for _, re := range regs {
						if re.MatchString(proxy) {
							expanded = append(expanded, proxy)
						}
					}
				}
			}
			proxies = append(proxies, expanded...)
			proxies = dedupNames(proxies)
			if len(proxies) == 0 && len(uses) == 0 {
				fallback := defaultEmptyFallback
				if fb, ok := weakString(gm["empty-fallback"]); ok && fb != "" {
					fallback = fb
				}
				proxies = []any{fallback}
			}
		}
		if includeProviders {
			uses = dedupNames(uses)
		}

		delete(gm, keyIncludeAll)
		delete(gm, keyIncludeAllProxies)
		delete(gm, keyIncludeAllProviders)
		if includeProxies {
			gm["proxies"] = proxies
		}
		if includeProviders {
			if len(uses) == 0 {
				delete(gm, "use")
			} else {
				gm["use"] = uses
			}
		}
		logIncludeAll(logs, fmt.Sprintf("策略组 %q: 展开 %d 个节点、%d 个提供者", name, len(proxies), len(uses)))
	}
}

func logIncludeAll(logs map[string][]string, msg string) {
	if logs == nil {
		return
	}
	logs[includeAllLogKey] = append(logs[includeAllLogKey], msg)
}

// proxyNames returns the `name` of every entry in a proxies list.
func proxyNames(v any) []string {
	var out []string
	for _, item := range toSlice(v) {
		if n := itemName(item); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// providerNames accepts both 自研内核's mapping form (proxy-providers keyed by
// name) and the list form used by some subscriptions.
func providerNames(v any) []string {
	switch x := v.(type) {
	case Mapping:
		out := make([]string, 0, len(x))
		for name := range x {
			out = append(out, name)
		}
		return out
	case []any:
		var out []string
		for _, item := range x {
			if n := itemName(item); n != "" {
				out = append(out, n)
			}
		}
		return out
	default:
		return nil
	}
}

// weakBool follows 自研内核's weakly typed decode: a bool or a non-zero number.
// The second return value is false when the value cannot be decoded.
func weakBool(v any) (bool, bool) {
	switch x := v.(type) {
	case nil:
		return false, true
	case bool:
		return x, true
	case int:
		return x != 0, true
	case int64:
		return x != 0, true
	case float64:
		return x != 0, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "", "false", "0", "no", "off":
			return false, true
		case "true", "1", "yes", "on":
			return true, true
		}
	}
	return false, false
}

// weakString follows 自研内核's weakly typed string decode for YAML scalars.
func weakString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	default:
		return "", false
	}
}

// compileFilters splits a 自研内核 `filter` on backticks and compiles each part.
func compileFilters(filter string) ([]*regexp.Regexp, error) {
	parts := strings.Split(filter, "`")
	regs := make([]*regexp.Regexp, 0, len(parts))
	for _, part := range parts {
		re, err := regexp.Compile(part)
		if err != nil {
			return nil, err
		}
		regs = append(regs, re)
	}
	return regs, nil
}

// dedupNames removes repeated name strings while keeping the first occurrence
// and preserving non-string entries (e.g. dialer-proxy) untouched.
func dedupNames(items []any) []any {
	seen := make(map[string]bool, len(items))
	out := make([]any, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			if seen[s] {
				continue
			}
			seen[s] = true
		}
		out = append(out, item)
	}
	return out
}
