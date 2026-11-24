// Package lastgood keeps a copy of the last successfully applied runtime
// config, so the boot guard can restore it after repeated failed starts.
package lastgood

import (
	"os"
	"path/filepath"
)

// Save stores a copy of the runtime config as the last known-good version.
func Save(dataDir string, runtimeYAML []byte) error {
	return os.WriteFile(filepath.Join(dataDir, "last-good.yaml"), runtimeYAML, 0o644)
}

// Load returns the last known-good config, or nil if none exists.
func Load(dataDir string) []byte {
	data, err := os.ReadFile(filepath.Join(dataDir, "last-good.yaml"))
	if err != nil {
		return nil
	}
	return data
}
