package ui

import (
	"testing"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/paths"
)

// TestViewSmoke renders every page in the headless tester to catch panics
// that only occur when a specific page's view builds.
func TestViewSmoke(t *testing.T) {
	if err := paths.Init("clashgo-test-view"); err != nil {
		t.Fatal(err)
	}
	// Inject temp config paths (NewAppForShot reads these).
	dir := t.TempDir()
	ConfigFile = dir + "/settings.yaml"
	RuntimeFile = dir + "/runtime.yaml"
	pages := []string{
		"/home", "/proxies", "/profiles", "/rules", "/connections",
		"/logs", "/unlock", "/dns", "/settings",
	}
	for _, p := range pages {
		t.Run(p, func(t *testing.T) {
			a, err := NewAppForShot(p)
			if err != nil {
				t.Fatal(err)
			}
			tester := ui.NewTester(a.View, 1000, 700)
			tester.Frame()
			tester.Frame()
		})
	}
}
