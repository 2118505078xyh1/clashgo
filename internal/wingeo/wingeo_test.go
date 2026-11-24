package wingeo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "geometry.json")
	if _, ok := Load(path); ok {
		t.Fatal("empty file should not load")
	}

	want := Geometry{X: 120, Y: 80, Width: 1280, Height: 800, Maximized: true}
	if err := Save(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok := Load(path)
	if !ok {
		t.Fatal("saved geometry not found")
	}
	if got != want {
		t.Fatalf("roundtrip = %+v, want %+v", got, want)
	}

	// Saving again must replace the file (exercises the Windows rename path).
	want = Geometry{X: -10, Y: 0, Width: 900, Height: 600}
	if err := Save(path, want); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, ok = Load(path)
	if !ok || got != want {
		t.Fatalf("overwritten = %+v (ok=%v), want %+v", got, ok, want)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	for _, data := range []string{"not json", `{"X":1,"Y":2,"Width":0,"Height":700}`} {
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, ok := Load(path); ok {
			t.Fatalf("invalid data %q should not load", data)
		}
	}
}

func TestClamp(t *testing.T) {
	cases := []struct {
		name                         string
		in                           Geometry
		minW, minH, screenW, screenH int
		want                         Geometry
	}{
		{"too small", Geometry{X: 10, Y: 10, Width: 10, Height: 10}, 820, 600, 1920, 1080, Geometry{X: 10, Y: 10, Width: 820, Height: 600}},
		{"offscreen right", Geometry{X: 1800, Y: 100, Width: 800, Height: 600}, 820, 600, 1920, 1080, Geometry{X: 1100, Y: 100, Width: 820, Height: 600}},
		{"negative origin", Geometry{X: -50, Y: -30, Width: 1000, Height: 700}, 820, 600, 1920, 1080, Geometry{X: 0, Y: 0, Width: 1000, Height: 700}},
		{"huge", Geometry{X: 40, Y: 40, Width: 5000, Height: 4000}, 820, 600, 1920, 1080, Geometry{X: 0, Y: 0, Width: 1920, Height: 1080}},
		{"no screen info", Geometry{X: -7, Y: -9, Width: 0, Height: 0}, 820, 600, 0, 0, Geometry{X: -7, Y: -9, Width: 820, Height: 600}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Clamp(tc.in, tc.minW, tc.minH, tc.screenW, tc.screenH); got != tc.want {
				t.Fatalf("Clamp = %+v, want %+v", got, tc.want)
			}
		})
	}
}
