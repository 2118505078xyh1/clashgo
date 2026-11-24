package profile

import (
	"time"

	"clashgo/internal/config"
)

// CreateComposition creates a "node pool" profile that merges proxies from
// several subscriptions (base + contributors).
func (m *Manager) CreateComposition(name, base string, contributors []string) (*config.PrfItem, error) {
	uid := newUID()
	item := &config.PrfItem{
		UID: uid, Type: config.ProfileComposition, Name: name,
		Updated: time.Now().Unix(),
		Option:  &config.PrfOption{},
		Composition: &config.CompositionSpec{
			Base:         base,
			Contributors: contributors,
		},
	}
	m.DB.Items = append(m.DB.Items, item)
	if m.DB.Current == "" {
		m.DB.Current = uid
	}
	return item, m.Save()
}
