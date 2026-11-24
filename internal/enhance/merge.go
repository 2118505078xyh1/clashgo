// Package enhance implements a reference GUI's profile enhancement pipeline:
// seq → merge → script → control-plane enforcement.
package enhance

import (
	"sort"
	"strings"

	"clashgo/internal/yaml"
)

// Mapping is a YAML mapping.
type Mapping = map[string]any

// LowercaseTop keys lowercases only top-level ASCII keys.
func LowercaseTop(m Mapping) Mapping {
	out := make(Mapping, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

// DeepMerge recursively merges overlay into base. Lists and scalars replace.
func DeepMerge(base, overlay Mapping) Mapping {
	for k, v := range overlay {
		if bm, ok := base[k].(Mapping); ok {
			if om, ok := v.(Mapping); ok {
				base[k] = DeepMerge(bm, om)
				continue
			}
		}
		base[k] = v
	}
	return base
}

// UseMerge applies a merge attachment to the config following verge rules:
// dns shallow merge, hosts replace, others deep merge, lists replace.
func UseMerge(config, merge Mapping) Mapping {
	config = LowercaseTop(config)
	merge = LowercaseTop(merge)

	// Split merge into field-level directives and bare keys. Directives apply
	// first so a later bare key can still override a whole field.
	dirs := Mapping{}
	bare := Mapping{}
	for k, v := range merge {
		if isDirective(k) {
			dirs[k] = v
		} else {
			bare[k] = v
		}
	}
	if len(dirs) > 0 {
		applyOverlayDirectives(config, dirs)
	}
	if len(bare) == 0 {
		return config
	}
	for k, v := range bare {
		if k == "dns" {
			if cm, ok := config[k].(Mapping); ok {
				if om, ok := v.(Mapping); ok {
					for sk, sv := range om {
						cm[sk] = sv // shallow: replace whole subkey
					}
					config[k] = cm
					continue
				}
			}
		}
		if k != "hosts" {
			if _, exists := config[k]; exists {
				if cm, ok := config[k].(Mapping); ok {
					if om, ok := v.(Mapping); ok {
						config[k] = DeepMerge(cm, om)
						continue
					}
				}
			}
		}
		config[k] = v
	}
	return config
}

// SeqMap is the content of a rules/proxies/groups attachment.
type SeqMap struct {
	Prepend []any    `yaml:"prepend"`
	Append  []any    `yaml:"append"`
	Delete  []string `yaml:"delete"`
}

// UseSeq applies prepend/append/delete to a config field.
func UseSeq(config Mapping, seq SeqMap, field string) Mapping {
	original := toSlice(config[field])
	deleted := make(map[string]bool, len(seq.Delete))
	for _, d := range seq.Delete {
		deleted[d] = true
	}
	var result []any
	result = append(result, seq.Prepend...)
	for _, item := range original {
		name := itemName(item)
		if name != "" && deleted[name] {
			continue
		}
		if s, ok := item.(string); ok && deleted[s] {
			continue
		}
		result = append(result, item)
	}
	result = append(result, seq.Append...)
	config[field] = result

	// proxies: inject new proxy names into the first selector group.
	if field == "proxies" {
		var newNames []string
		for _, item := range append(append([]any{}, seq.Prepend...), seq.Append...) {
			if n := itemName(item); n != "" {
				newNames = append(newNames, n)
			}
		}
		dedup := make(map[string]bool)
		var unique []string
		for _, n := range newNames {
			if !dedup[n] {
				dedup[n] = true
				unique = append(unique, n)
			}
		}
		if len(unique) > 0 {
			groups := toSlice(config["proxy-groups"])
			for _, g := range groups {
				gm, ok := g.(Mapping)
				if !ok {
					continue
				}
				gt, _ := gm["type"].(string)
				if strings.ToLower(gt) != "select" && strings.ToLower(gt) != "selector" {
					continue
				}
				pl := toSlice(gm["proxies"])
				var filtered []any
				for _, p := range pl {
					if s, ok := p.(string); ok && deleted[s] {
						continue
					}
					filtered = append(filtered, p)
				}
				existing := map[string]bool{}
				for _, p := range filtered {
					if s, ok := p.(string); ok {
						existing[s] = true
					}
				}
				var prepend []any
				for _, n := range unique {
					if !existing[n] {
						prepend = append(prepend, n)
					}
				}
				gm["proxies"] = append(prepend, filtered...)
				break // only the first selector group
			}
		}
	}
	return config
}

func toSlice(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case nil:
		return []any{}
	default:
		return []any{x}
	}
}

func toStringSlice(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func itemName(item any) string {
	switch x := item.(type) {
	case string:
		return x
	case Mapping:
		if n, ok := x["name"].(string); ok {
			return n
		}
	}
	return ""
}

// SortKeys returns a deterministically ordered mapping for output.
func SortKeys(m Mapping, priorityFirst, listLast []string) *yaml.OrderedMap {
	node := yaml.NewOrderedMap()
	seen := map[string]bool{}
	add := func(k string) {
		v, ok := m[k]
		if !ok || seen[k] {
			return
		}
		seen[k] = true
		node.Set(k, v)
	}
	for _, k := range priorityFirst {
		add(k)
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	for _, k := range listLast {
		add(k)
	}
	return node
}
