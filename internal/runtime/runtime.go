// Package runtime generates the effective 自研内核 config from a user profile
// plus clashgo settings, using the full enhance pipeline.
package runtime

import (
	"fmt"
	"os"

	"clashgo/internal/config"
	"clashgo/internal/enhance"
)

// LastLogs holds script logs from the most recent Generate call.
var LastLogs map[string][]string

// LastSteps holds the pipeline step diffs from the most recent Generate call.
var LastSteps []enhance.Step

// Generate runs the enhance pipeline and writes the generated config.
func Generate(profileBytes []byte, s *config.Settings, profile *config.PrfItem, db *config.ProfilesDB, runtimePath string) ([]byte, error) {
	result, err := enhance.Execute(profileBytes, profile, db, s)
	if err != nil {
		return nil, fmt.Errorf("enhance: %w", err)
	}
	LastLogs = result.Logs
	LastSteps = result.Steps
	data, err := enhance.Marshal(result.Config)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(runtimePath, data, 0o644); err != nil {
		return nil, err
	}
	return data, nil
}
