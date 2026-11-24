package main

import (
	"testing"
	"time"

	"clashgo/internal/config"
	"clashgo/internal/controller"
	"clashgo/internal/kernel"
	"clashgo/internal/paths"
	"clashgo/internal/profile"
	"clashgo/internal/runtime"
)

func TestEmbeddedCoreStarts(t *testing.T) {
	if err := paths.Init("clashgo-test"); err != nil {
		t.Fatal(err)
	}
	s := config.DefaultSettings()
	s.ExternalController = "127.0.0.1:29197"
	s.MixedPort = 27897

	k := kernel.New()
	data, err := runtime.Generate([]byte(profile.DefaultProfile), s, nil, nil, paths.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.ApplyWithController(data, s.ExternalController, s.Secret); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !k.Started() {
		t.Fatal("kernel not started")
	}
	// Poll instead of a fixed sleep — usually ready in a few milliseconds.
	cli := controller.New(s.ExternalController, s.Secret)
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := cli.Version(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("REST API not reachable: %v", lastErr)
}
