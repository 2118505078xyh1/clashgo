package config

import (
	"errors"
	"os"

	"clashgo/internal/yaml"
)

// LoadSettings reads settings.yaml, falling back to defaults if absent.
func LoadSettings(path string) (*Settings, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return nil, err
	}
	s := DefaultSettings()
	if err := yaml.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// SaveSettings writes settings.yaml atomically-ish.
func SaveSettings(path string, s *Settings) error {
	data, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadProfiles reads profiles.yaml. Missing file yields an empty DB.
func LoadProfiles(path string) (*ProfilesDB, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &ProfilesDB{}, nil
	}
	if err != nil {
		return nil, err
	}
	p := &ProfilesDB{}
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, err
	}
	if p.Items == nil {
		p.Items = []*PrfItem{}
	}
	return p, nil
}

// SaveProfiles writes profiles.yaml.
func SaveProfiles(path string, p *ProfilesDB) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
