// Package snapshot captures and restores config files around critical writes,
// so a failed apply can roll back to the last known-good state.
package snapshot

import (
	"os"
	"path/filepath"
	"sync"
)

// Snapshot holds copies of a set of files.
type Snapshot struct {
	files map[string][]byte
	mu    sync.Mutex
}

// Capture reads the given files into memory (missing files are skipped).
func Capture(paths ...string) *Snapshot {
	s := &Snapshot{files: map[string][]byte{}}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			s.files[p] = data
		}
	}
	return s
}

// Restore writes all captured files back.
func (s *Snapshot) Restore() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	for p, data := range s.files {
		if err := os.WriteFile(p, data, 0o644); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// CaptureDir captures every regular file in a directory (non-recursive).
func CaptureDir(dir string) *Snapshot {
	s := &Snapshot{files: map[string][]byte{}}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if data, err := os.ReadFile(p); err == nil {
			s.files[p] = data
		}
	}
	return s
}
