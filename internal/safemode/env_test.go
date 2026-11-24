package safemode

import "testing"

func TestNonInteractive(t *testing.T) {
	// Neither signal set -> interactive launch.
	t.Setenv("CLASHGO_NONINTERACTIVE", "")
	t.Setenv("CI", "")
	if NonInteractive() || AcceptDisclaimer() {
		t.Fatalf("expected interactive mode with both env vars empty")
	}

	// CI=true alone is enough.
	t.Setenv("CI", "true")
	if !NonInteractive() || !AcceptDisclaimer() {
		t.Fatalf("CI=true should enable non-interactive mode and accept the disclaimer")
	}

	// CLASHGO_NONINTERACTIVE=1 alone is enough.
	t.Setenv("CI", "")
	t.Setenv("CLASHGO_NONINTERACTIVE", "1")
	if !NonInteractive() || !AcceptDisclaimer() {
		t.Fatalf("CLASHGO_NONINTERACTIVE=1 should enable non-interactive mode")
	}

	// Other values must not trigger it.
	t.Setenv("CLASHGO_NONINTERACTIVE", "0")
	if NonInteractive() {
		t.Fatalf("CLASHGO_NONINTERACTIVE=0 must not enable non-interactive mode")
	}
}
