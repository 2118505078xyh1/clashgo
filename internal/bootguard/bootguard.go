// Package bootguard tracks startup phases so repeated crashes can trigger a
// fallback to a known-good config (idea from common practice.dart).
package bootguard

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// State is the persisted boot record.
type State struct {
	Phase      string `json:"phase"` // starting | running | closed
	FailStreak int    `json:"fail_streak"`
	LastError  string `json:"last_error,omitempty"`
}

// Guard manages the boot record.
type Guard struct {
	path string
}

// New opens (or creates) the boot record at dataDir/boot.json.
func New(dataDir string) *Guard {
	return &Guard{path: filepath.Join(dataDir, "boot.json")}
}

// Read loads the previous boot record.
func (g *Guard) Read() State {
	data, err := os.ReadFile(g.path)
	if err != nil {
		return State{}
	}
	var s State
	if json.Unmarshal(data, &s) != nil {
		return State{}
	}
	return s
}

// Write persists a boot record.
func (g *Guard) Write(s State) error {
	data, _ := json.Marshal(s)
	return os.WriteFile(g.path, data, 0o644)
}

// MarkStarting records a startup attempt. If the previous run never reached
// "running", the failure streak increases.
func (g *Guard) MarkStarting() State {
	prev := g.Read()
	streak := prev.FailStreak
	if prev.Phase == "starting" {
		streak++
	}
	s := State{Phase: "starting", FailStreak: streak}
	_ = g.Write(s)
	return s
}

// MarkRunning records a successful startup and clears the streak.
func (g *Guard) MarkRunning() {
	_ = g.Write(State{Phase: "running", FailStreak: 0})
}

// MarkClosed records a clean shutdown.
func (g *Guard) MarkClosed() {
	s := g.Read()
	s.Phase = "closed"
	_ = g.Write(s)
}
