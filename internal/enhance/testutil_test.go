package enhance

import (
	"os"
	"path/filepath"
	"testing"

	"clashgo/internal/paths"
)

// freshProfileDir isolates attachment files for one test.
func freshProfileDir(t *testing.T) {
	t.Helper()
	paths.Profiles = t.TempDir()
}

// tempFile writes an attachment into the current Profiles dir.
func tempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(paths.Profiles, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}
