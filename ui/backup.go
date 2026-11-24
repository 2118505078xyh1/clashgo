package ui

import (
	"log"

	"clashgo/internal/backup"
	"clashgo/internal/profile"
)

func loadProfiles() (*profile.Manager, error) {
	return profile.New()
}

func (a *App) refreshBackups() {
	list, err := backup.List()
	if err != nil {
		a.notify("错误", err.Error())
		return
	}
	a.Backups = list
}

func (a *App) restoreBackup(name string) {
	if err := backup.Restore(name); err != nil {
		a.notify("恢复失败", err.Error())
		return
	}
	// Reload in-memory state from restored files.
	pm, err := loadProfiles()
	if err != nil {
		a.notify("恢复失败", err.Error())
		return
	}
	a.Profiles = pm
	if err := a.applyCurrentProfile(); err != nil {
		log.Printf("reapply after restore: %v", err)
	}
	a.notify("恢复完成", "已从备份 "+name+" 恢复，内核已重载")
}
