// Command shot renders clashgo's UI headlessly to PNG files, bypassing
// the GPU/screen. Usage: go run ./cmd/shot
package main

import (
	"image/png"
	"log"
	"os"

	"github.com/egoist/mygo/ui"

	"clashgo/internal/paths"
	cgui "clashgo/ui"
)

func main() {
	if err := paths.Init("clashgo-shot"); err != nil {
		log.Fatal(err)
	}
	cgui.ConfigFile = paths.Settings
	cgui.RuntimeFile = paths.Runtime

	pages := []struct {
		path string
		file string
	}{
		{"/home", "shot-home.png"},
		{"/proxies", "shot-proxies.png"},
		{"/profiles", "shot-profiles.png"},
		{"/rules", "shot-rules.png"},
		{"/connections", "shot-connections.png"},
		{"/logs", "shot-logs.png"},
		{"/unlock", "shot-unlock.png"},
		{"/dns", "shot-dns.png"},
		{"/requests", "shot-requests.png"},
		{"/settings", "shot-settings.png"},
	}
	for _, p := range pages {
		// Fresh App per page so the router's element state binds to this
		// Tester's runtime (a router cannot be shared across testers).
		a, err := cgui.NewAppForShot(p.path)
		if err != nil {
			log.Fatal(err)
		}
		t := ui.NewTester(a.View, 1100, 1000)
		f, err := os.Create(p.file)
		if err != nil {
			log.Fatal(err)
		}
		if err := png.Encode(f, t.Image()); err != nil {
			log.Fatal(err)
		}
		f.Close()
		log.Printf("rendered %s -> %s", p.path, p.file)
	}
}
