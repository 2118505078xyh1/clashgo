package main

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"clashgo/internal/installer"
)

//go:embed payload/*
var payload embed.FS

func main() {
	installer.SetEmbeddedFS(payload)
	dir := os.Getenv("PROBE_INSTALL_DIR")
	if dir == "" {
		tmp, _ := os.MkdirTemp("", "install-probe-")
		defer os.RemoveAll(tmp)
		dir = filepath.Join(tmp, "ClashGo")
	}
	fmt.Println("安装目录:", dir)
	err := installer.Run(installer.Options{
		InstallDir: dir, DesktopShortcut: true, StartMenuShortcut: true, AutoStart: true,
	}, func(p int, m string) { fmt.Printf("[%d%%] %s\n", p, m) })
	fmt.Println("install err:", err)

	for _, f := range []string{"clashgo.exe", "app-icon.ico", "data"} {
		p := filepath.Join(dir, f)
		if st, e := os.Stat(p); e == nil {
			fmt.Printf("  %s OK (%d)\n", f, st.Size())
		} else {
			fmt.Printf("  %s MISSING: %v\n", f, e)
		}
	}
	desk, e := installer.DesktopPath()
	fmt.Println("desktop:", desk, "err:", e)
	if desk != "" {
		lnk := installer.ShortcutPath(desk, "ClashGo")
		if st, e := os.Stat(lnk); e == nil {
			fmt.Println("  desktop lnk OK", st.Size())
		} else {
			fmt.Println("  desktop lnk MISSING:", e)
		}
	}
}
