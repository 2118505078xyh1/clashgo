// Package wingeo persists the main window's position and size as JSON.
// It has no dependency on any UI toolkit so it can be used by main.go and
// tested headlessly.
package wingeo

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Geometry is the saved state of a window. X/Y are the top-left corner in
// screen coordinates; Width/Height are the outer window size in DIPs.
type Geometry struct {
	X, Y, Width, Height int
	Maximized           bool
}

// Load reads a saved geometry. The second result reports whether a valid
// geometry was found; callers should fall back to defaults when it is false.
func Load(path string) (Geometry, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Geometry{}, false
	}
	var g Geometry
	if err := json.Unmarshal(data, &g); err != nil {
		return Geometry{}, false
	}
	if g.Width <= 0 || g.Height <= 0 {
		return Geometry{}, false
	}
	return g, true
}

// Save writes g as JSON. The write is atomic on POSIX systems: data goes to
// a temporary file in the same directory which is then renamed into place.
// On Windows an existing destination must be removed before renaming.
func Save(path string, g Geometry) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wingeo-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		// Windows cannot rename over an existing file; drop it and retry.
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return err
		}
		if retryErr := os.Rename(name, path); retryErr != nil {
			return retryErr
		}
	}
	return nil
}

// Clamp keeps a geometry usable: at least minW×minH, never larger than the
// screen, and fully on-screen when screen dimensions are known (<=0 skips
// the screen constraint).
func Clamp(g Geometry, minW, minH, screenW, screenH int) Geometry {
	if minW < 1 {
		minW = 1
	}
	if minH < 1 {
		minH = 1
	}
	if g.Width < minW {
		g.Width = minW
	}
	if g.Height < minH {
		g.Height = minH
	}
	if screenW > 0 {
		if g.Width > screenW && screenW >= minW {
			g.Width = screenW
		}
		if g.X < 0 {
			g.X = 0
		}
		if maxX := screenW - g.Width; maxX >= 0 && g.X > maxX {
			g.X = maxX
		}
	}
	if screenH > 0 {
		if g.Height > screenH && screenH >= minH {
			g.Height = screenH
		}
		if g.Y < 0 {
			g.Y = 0
		}
		if maxY := screenH - g.Height; maxY >= 0 && g.Y > maxY {
			g.Y = maxY
		}
	}
	return g
}
