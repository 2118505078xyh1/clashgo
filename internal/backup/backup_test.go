package backup

import (
	"os"
	"path/filepath"
	"testing"

	"clashgo/internal/paths"
)

// setupPaths points the paths package globals at a throwaway directory and
// restores the previous values when the test finishes.
func setupPaths(t *testing.T) {
	t.Helper()
	old := struct {
		Home, Backup, Profiles, Settings, ProfilesDB string
	}{paths.Home, paths.Backup, paths.Profiles, paths.Settings, paths.ProfilesDB}
	t.Cleanup(func() {
		paths.Home = old.Home
		paths.Backup = old.Backup
		paths.Profiles = old.Profiles
		paths.Settings = old.Settings
		paths.ProfilesDB = old.ProfilesDB
	})

	root := t.TempDir()
	paths.Home = filepath.Join(root, "home")
	paths.Backup = filepath.Join(root, "backup")
	paths.Profiles = filepath.Join(paths.Home, "profiles")
	paths.Settings = filepath.Join(paths.Home, "settings.yaml")
	paths.ProfilesDB = filepath.Join(paths.Home, "profiles.yaml")
	for _, d := range []string{paths.Home, paths.Backup, paths.Profiles} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCreateZipRestoreZipRoundTrip(t *testing.T) {
	setupPaths(t)

	writeFile(t, paths.Settings, "port: 7890\n")
	writeFile(t, paths.ProfilesDB, "items:\n  - uid: abc\n")
	profile := filepath.Join(paths.Profiles, "abc.yaml")
	writeFile(t, profile, "proxies: []\n")

	zipPath, err := CreateZip("roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("zip not created at %s: %v", zipPath, err)
	}
	if want := filepath.Join(paths.Backup, "roundtrip.zip"); zipPath != want {
		t.Fatalf("zip path = %q, want %q", zipPath, want)
	}

	// Simulate config changes after the backup was taken.
	writeFile(t, paths.Settings, "port: 9999\n")
	writeFile(t, paths.ProfilesDB, "items: []\n")
	writeFile(t, profile, "proxies: [changed]\n")

	if err := RestoreZip(zipPath); err != nil {
		t.Fatal(err)
	}

	if got := readFile(t, paths.Settings); got != "port: 7890\n" {
		t.Fatalf("settings after restore = %q", got)
	}
	if got := readFile(t, paths.ProfilesDB); got != "items:\n  - uid: abc\n" {
		t.Fatalf("profiles db after restore = %q", got)
	}
	if got := readFile(t, profile); got != "proxies: []\n" {
		t.Fatalf("profile after restore = %q", got)
	}

	// The temporary extraction directory must be cleaned up.
	entries, err := os.ReadDir(paths.Backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) >= 8 && e.Name()[:8] == "restore-" {
			t.Fatalf("temporary extract dir left behind: %s", e.Name())
		}
	}
}

func TestSafeRestore(t *testing.T) {
	setupPaths(t)

	writeFile(t, paths.Settings, "port: 1111\n")
	writeFile(t, paths.ProfilesDB, "state: old\n")

	// Rename the freshly-created backup to a stable name so that the second
	// backup made by SafeRestore can never collide with it.
	name, err := Create()
	if err != nil {
		t.Fatal(err)
	}
	stable := filepath.Join(paths.Backup, "stable")
	if err := os.Rename(filepath.Join(paths.Backup, name), stable); err != nil {
		t.Fatal(err)
	}
	name = "stable"

	writeFile(t, paths.Settings, "port: 2222\n")
	writeFile(t, paths.ProfilesDB, "state: new\n")

	if err := SafeRestore(name); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, paths.Settings); got != "port: 1111\n" {
		t.Fatalf("settings after safe restore = %q", got)
	}
	if got := readFile(t, paths.ProfilesDB); got != "state: old\n" {
		t.Fatalf("profiles db after safe restore = %q", got)
	}

	// SafeRestore must leave the pre-restore backup available for rollback.
	backups, err := List()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range backups {
		if b.Name != name {
			found = true
		}
	}
	if !found {
		t.Fatalf("pre-restore backup was not kept: %+v", backups)
	}

	if err := SafeRestore("does-not-exist"); err == nil {
		t.Fatal("expected error restoring a missing backup")
	}
}
