package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"clashgo/internal/config"
	"clashgo/internal/paths"
)

// Default templates matching a reference GUI.
const (
	MergeTemplate = `# Profile Enhancement Merge Template for ClashGo

profile:
  store-selected: true
`
	ScriptTemplate = `// Define main function (script entry)

function main(config, profileName) {
  return config;
}
`
	SeqTemplate = `prepend: []
append: []
delete: []
`
)

// CreateAttachment creates a merge/script/rules/proxies/groups companion
// attachment and wires its UID into the parent profile's Option.
func (m *Manager) CreateAttachment(parentUID string, kind config.ProfileType, name, content string) (*config.PrfItem, error) {
	parent := m.DB.Find(parentUID)
	if parent == nil {
		return nil, fmt.Errorf("parent profile not found")
	}
	prefix := map[config.ProfileType]string{
		config.ProfileMerge: "m", config.ProfileScript: "s",
		config.ProfileRules: "r", config.ProfileProxies: "p", config.ProfileGroups: "g",
	}[kind]
	if prefix == "" {
		return nil, fmt.Errorf("invalid attachment type: %s", kind)
	}
	uid := prefix + newUID()[:6]
	ext := ".yaml"
	if kind == config.ProfileScript {
		ext = ".js"
	}
	file := uid + ext
	if err := os.WriteFile(filepath.Join(paths.Profiles, file), []byte(content), 0o644); err != nil {
		return nil, err
	}
	item := &config.PrfItem{
		UID: uid, Type: kind, Name: name, File: file, Updated: time.Now().Unix(),
	}
	m.DB.Items = append(m.DB.Items, item)
	if parent.Option == nil {
		parent.Option = &config.PrfOption{}
	}
	switch kind {
	case config.ProfileMerge:
		parent.Option.Merge = uid
	case config.ProfileScript:
		parent.Option.Script = uid
	case config.ProfileRules:
		parent.Option.Rules = uid
	case config.ProfileProxies:
		parent.Option.Proxies = uid
	case config.ProfileGroups:
		parent.Option.Groups = uid
	}
	return item, m.Save()
}

// AttachmentUID returns the UID of an attachment referenced by a profile.
func AttachmentUID(opt *config.PrfOption, kind config.ProfileType) string {
	if opt == nil {
		return ""
	}
	switch kind {
	case config.ProfileMerge:
		return opt.Merge
	case config.ProfileScript:
		return opt.Script
	case config.ProfileRules:
		return opt.Rules
	case config.ProfileProxies:
		return opt.Proxies
	case config.ProfileGroups:
		return opt.Groups
	}
	return ""
}
