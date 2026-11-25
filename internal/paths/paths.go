// Package paths resolves clashgo's data directories.
package paths

import (
	"os"
	"path/filepath"
)

var (
	Home       string // application data root
	Profiles   string // profile yaml files
	Logs       string // logs
	Icons      string // cached icons
	Backup     string // local backups
	Runtime    string // generated runtime config path
	Settings   string // clashgo settings yaml
	ProfilesDB string // profiles.yaml
)

// Init resolves and creates all data directories.
func Init(appName string) error {
	base, err := os.UserConfigDir()
	if err != nil {
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		base = filepath.Join(home, ".config")
	}
	Home = filepath.Join(base, appName)

	// 便携模式：若 exe 同目录存在 data 目录，则用它作为数据根，
	// 让绿色版把所有配置/订阅放在程序目录下（例如 <安装目录>/data）。
	if exe, e := os.Executable(); e == nil {
		localData := filepath.Join(filepath.Dir(exe), "data")
		if st, e2 := os.Stat(localData); e2 == nil && st.IsDir() {
			Home = localData
		}
	}
	Profiles = filepath.Join(Home, "profiles")
	Logs = filepath.Join(Home, "logs")
	Icons = filepath.Join(Home, "icons")
	Backup = filepath.Join(Home, "backup")
	Runtime = filepath.Join(Home, "runtime.yaml")
	Settings = filepath.Join(Home, "settings.yaml")
	ProfilesDB = filepath.Join(Home, "profiles.yaml")

	for _, d := range []string{Home, Profiles, Logs, Icons, Backup} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
