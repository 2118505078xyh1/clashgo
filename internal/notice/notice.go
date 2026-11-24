// Package notice provides a typed notification system with severity levels,
// deduplication and i18n code mapping. Inspired by a reference GUI's
// NoticeStatus enum + notice-service.
package notice

import (
	"sync"
	"time"
)

// Level is a notification severity.
type Level int

const (
	Info Level = iota
	Success
	Warning
	Error
)

// Duration returns the default auto-dismiss duration for a level.
func (l Level) Duration() time.Duration {
	switch l {
	case Error:
		return 8 * time.Second
	case Warning:
		return 6 * time.Second
	case Success:
		return 3 * time.Second
	default:
		return 5 * time.Second
	}
}

// Item is one notification.
type Item struct {
	Code      string
	Message   string
	Level     Level
	CreatedAt time.Time
	Duration  time.Duration
}

// Manager stores notifications with dedup by code.
type Manager struct {
	mu    sync.Mutex
	items []Item
	max   int
}

// New creates a manager.
func New(max int) *Manager {
	if max < 1 {
		max = 50
	}
	return &Manager{max: max}
}

// Push adds a notification. If a notification with the same code exists,
// it is replaced (dedup) so repeated errors don't stack up.
func (m *Manager) Push(code, message string, level Level) Item {
	m.mu.Lock()
	defer m.mu.Unlock()
	it := Item{Code: code, Message: message, Level: level, CreatedAt: time.Now(), Duration: level.Duration()}
	for i := range m.items {
		if m.items[i].Code == code {
			// Keep original position but refresh content/time.
			m.items[i] = it
			return it
		}
	}
	m.items = append(m.items, it)
	if len(m.items) > m.max {
		m.items = m.items[len(m.items)-m.max:]
	}
	return it
}

// List returns a snapshot of current notifications, newest last.
func (m *Manager) List() []Item {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Item(nil), m.items...)
}

// Clear removes all notifications.
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = nil
}

// Code definitions for consistent error/warning messages.
const (
	CoreStartFailed      = "core_start::error"
	ConfigInvalid        = "config_validate::invalid"
	ConfigRollback       = "config_apply::rollback"
	PortFallback         = "mixed_port::fallback"
	SysproxyGuardStopped = "sysproxy_guard::stopped"
	ProfileImportOK      = "profile_import::ok"
	ProfileImportFailed  = "profile_import::failed"
	UpdateAvailable      = "update::available"
	BackupOK             = "backup::ok"
)
