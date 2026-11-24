package enhance

import (
	"fmt"
	"os"
	"path/filepath"

	"clashgo/internal/yaml"

	"clashgo/internal/config"
	"clashgo/internal/paths"
)

// loadRaw reads a profile's YAML into a lowercase Mapping.
func loadRaw(item *config.PrfItem) (Mapping, error) {
	if item == nil || item.File == "" {
		return nil, fmt.Errorf("invalid profile")
	}
	data, err := readProfileFile(item.File)
	if err != nil {
		return nil, err
	}
	var m Mapping
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return LowercaseTop(m), nil
}

// ResolveComposition builds a synthetic config from a composition profile:
// base fields are inherited, contributor proxies are appended in order, and
// duplicates are NOT removed (matching a reference GUI; 自研内核 decides the winner).
func ResolveComposition(item *config.PrfItem, db *config.ProfilesDB) (Mapping, map[string][]string, error) {
	logs := map[string][]string{"composition": {}}
	spec := item.Composition
	if spec == nil {
		return nil, nil, fmt.Errorf("composition spec missing")
	}
	seen := map[string]bool{}
	check := func(uid string) (*config.PrfItem, error) {
		m := db.Find(uid)
		if m == nil || uid == item.UID {
			return nil, fmt.Errorf("invalid composition member %s", uid)
		}
		if m.Type == config.ProfileComposition || isAttachment(m.Type) {
			return nil, fmt.Errorf("composition member %s must be a config profile", uid)
		}
		return m, nil
	}
	var cfg Mapping
	if spec.Base != "" {
		base, err := check(spec.Base)
		if err != nil {
			return nil, nil, err
		}
		cfg, err = loadRaw(base)
		if err != nil {
			return nil, nil, err
		}
		seen[spec.Base] = true
	} else {
		cfg = Mapping{"proxies": []any{}}
	}
	for _, uid := range spec.Contributors {
		if seen[uid] || uid == spec.Base {
			return nil, nil, fmt.Errorf("duplicate contributor %s", uid)
		}
		seen[uid] = true
		member, err := check(uid)
		if err != nil {
			return nil, nil, err
		}
		m, err := loadRaw(member)
		if err != nil {
			return nil, nil, err
		}
		proxies := toSlice(m["proxies"])
		if len(proxies) == 0 {
			logs["composition"] = append(logs["composition"], "member "+uid+" has no proxies")
			continue
		}
		cfg = UseSeq(cfg, SeqMap{Append: proxies}, "proxies") // also injects into first selector
	}
	// Warn about duplicate names (no silent renaming).
	names := map[string]bool{}
	for _, p := range toSlice(cfg["proxies"]) {
		if n, ok := p.(Mapping); ok {
			if name, _ := n["name"].(string); name != "" {
				if names[name] {
					logs["composition"] = append(logs["composition"], "duplicate proxy name: "+name)
				}
				names[name] = true
			}
		}
	}
	return cfg, logs, nil
}

func isAttachment(t config.ProfileType) bool {
	switch t {
	case config.ProfileMerge, config.ProfileScript, config.ProfileRules,
		config.ProfileProxies, config.ProfileGroups:
		return true
	}
	return false
}

// readProfileFile reads a profile file from the profiles directory.
var readProfileFile = func(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(paths.Profiles, name))
}
