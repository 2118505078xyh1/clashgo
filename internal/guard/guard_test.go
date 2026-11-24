package guard

import (
	"context"
	"sync"
	"testing"
)

type fakeApplier struct {
	mu       sync.Mutex
	enable   bool
	server   string
	setCalls int
	failNext bool
}

func (f *fakeApplier) Get() (bool, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enable, f.server, "", nil
}
func (f *fakeApplier) Set(e bool, s, b string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return errFake
	}
	f.enable, f.server = e, s
	f.setCalls++
	return nil
}

type testErr struct{}

func (testErr) Error() string { return "fake error" }

var errFake = testErr{}

func TestGuardRestoresDrift(t *testing.T) {
	app := &fakeApplier{enable: false, server: ""}
	g := New(app, "127.0.0.1:7897", "", 1, nil)
	// Call check directly instead of waiting for the ticker (keeps tests fast).
	g.mu.Lock()
	gen := g.generation
	g.mu.Unlock()
	g.check(context.Background(), gen)
	app.mu.Lock()
	calls := app.setCalls
	app.mu.Unlock()
	if calls == 0 {
		t.Error("guard did not restore drifted proxy")
	}
}

func TestGuardGenerationSupersedes(t *testing.T) {
	app := &fakeApplier{enable: false, server: ""}
	g := New(app, "127.0.0.1:7897", "", 1, nil)
	g.Start()
	g.Stop()
	// A superseded generation must not write.
	g.mu.Lock()
	g.generation++
	gen := g.generation - 1
	g.mu.Unlock()
	g.check(context.Background(), gen) // stale gen -> no-op
	app.mu.Lock()
	calls := app.setCalls
	app.mu.Unlock()
	if calls != 0 {
		t.Error("stale guard wrote proxy settings")
	}
}
