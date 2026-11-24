package enhance

import (
	"strconv"
	"strings"
)

// applyOverlayDirectives handles a reference GUI-style field-level merge directives.
// Keys with these prefixes operate on dotted paths:
//
//	prepend__proxy-groups.0.proxies / append__... : prepend/append to a list
//	override__dns.fake-ip-range                    : replace a value (no create if absent)
//	remove__rules.2                                 : delete a list item / map key
//
// Bare keys keep the normal deep-merge behavior.
func applyOverlayDirectives(config, merge Mapping) {
	// Deterministic order: directives before bare keys.
	var directives, bare []string
	for k := range merge {
		if isDirective(k) {
			directives = append(directives, k)
		} else {
			bare = append(bare, k)
		}
	}
	sortStrings(directives)
	sortStrings(bare)

	for _, k := range directives {
		key := strings.ToLower(k)
		val := merge[k]
		path := strings.ToLower(directivePath(key))
		switch {
		case strings.HasPrefix(key, "prepend__") || strings.HasPrefix(key, "prepend-"):
			modifyList(config, path, val, true)
		case strings.HasPrefix(key, "append__") || strings.HasPrefix(key, "append-"):
			modifyList(config, path, val, false)
		case strings.HasPrefix(key, "override__") || strings.HasPrefix(key, "override-"):
			setAtPath(config, path, val, false)
		case strings.HasPrefix(key, "remove__") || strings.HasPrefix(key, "remove-"):
			removeAtPath(config, path)
		}
	}
	for _, k := range bare {
		config[k] = merge[k]
	}
}

func isDirective(k string) bool {
	l := strings.ToLower(k)
	for _, p := range []string{"prepend__", "prepend-", "append__", "append-", "override__", "override-", "remove__", "remove-"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

func directivePath(k string) string {
	if i := strings.Index(k, "__"); i >= 0 {
		return k[i+2:]
	}
	if i := strings.Index(k, "-"); i >= 0 {
		return k[i+1:]
	}
	return k
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	return strings.Split(path, ".")
}

// getAtPath resolves a dotted path; numeric segments index lists.
func getAtPath(root any, parts []string) (any, bool) {
	cur := root
	for _, part := range parts {
		switch x := cur.(type) {
		case Mapping:
			v, ok := x[part]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			cur = x[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// setAtPath sets a value at a dotted path. create=false means a missing path
// is skipped (override semantics); create=true builds intermediate maps.
func setAtPath(root Mapping, path string, val any, create bool) {
	parts := splitPath(path)
	if len(parts) == 0 {
		return
	}
	cur := any(root)
	for _, part := range parts[:len(parts)-1] {
		next, ok := getAtPath(cur, []string{part})
		if !ok {
			if !create {
				return
			}
			switch x := cur.(type) {
			case Mapping:
				x[part] = Mapping{}
				next = x[part]
			default:
				return
			}
		}
		cur = next
	}
	last := parts[len(parts)-1]
	switch x := cur.(type) {
	case Mapping:
		x[last] = val
	case []any:
		i, err := strconv.Atoi(last)
		if err == nil && i >= 0 && i < len(x) {
			x[i] = val
		}
	}
}

func modifyList(root Mapping, path string, val any, prepend bool) {
	target, ok := getAtPath(root, splitPath(path))
	if !ok {
		return
	}
	list, ok := toSliceAny(target)
	if !ok {
		return
	}
	var additions []any
	switch v := val.(type) {
	case []any:
		additions = v
	default:
		additions = []any{val}
	}
	var out []any
	if prepend {
		out = append(out, additions...)
		out = append(out, list...)
	} else {
		out = append(out, list...)
		out = append(out, additions...)
	}
	setAtPath(root, path, out, false)
}

func toSliceAny(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case []string:
		out := make([]any, len(x))
		for i := range x {
			out[i] = x[i]
		}
		return out, true
	default:
		return nil, false
	}
}

func removeAtPath(root Mapping, path string) {
	parts := splitPath(path)
	if len(parts) == 0 {
		return
	}
	last := parts[len(parts)-1]
	parent, ok := getAtPath(root, parts[:len(parts)-1])
	if !ok {
		return
	}
	switch x := parent.(type) {
	case Mapping:
		delete(x, last)
	case []any:
		i, err := strconv.Atoi(last)
		if err == nil && i >= 0 && i < len(x) {
			copy(x[i:], x[i+1:])
			setAtPath(root, strings.Join(parts[:len(parts)-1], "."), x[:len(x)-1], false)
		}
	}
}
