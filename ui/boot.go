package ui

import (
	"os"
	"path/filepath"

	"clashgo/internal/config"
	"clashgo/internal/lastgood"
	"clashgo/internal/paths"
	"clashgo/internal/profile"
)

// ResetToDefaultProfile restores the last known-good runtime config after
// repeated failed startups, falling back to the minimal default config if
// no good snapshot exists.
func ResetToDefaultProfile() {
	good := lastgood.Load(paths.Home)
	if len(good) > 0 {
		_ = os.WriteFile(paths.Runtime, good, 0o644)
		return
	}
	db, err := config.LoadProfiles(paths.ProfilesDB)
	if err != nil || db.Current == "" {
		return
	}
	item := db.Find(db.Current)
	if item == nil {
		return
	}
	_ = os.WriteFile(filepath.Join(paths.Profiles, item.File), []byte(profile.DefaultProfile), 0o644)
}
