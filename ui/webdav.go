package ui

import (
	"clashgo/internal/backup"
	"clashgo/internal/webdav"
)

func (a *App) webdavClient() *webdav.Client {
	return webdav.New(webdav.Config{
		URL: a.Settings.WebDAVURL, Username: a.Settings.WebDAVUsername,
		Password: a.Settings.WebDAVPassword,
	})
}

func (a *App) webdavUpload() {
	go func() {
		name, err := backup.Create()
		if err != nil {
			a.win.Update(func() { a.notify("备份失败", err.Error()) })
			return
		}
		if err := a.webdavClient().Create(name); err != nil {
			a.win.Update(func() { a.notify("上传失败", err.Error()) })
			return
		}
		a.win.Update(func() { a.notify("上传成功", "备份 "+name+" 已上传到 WebDAV") })
	}()
}

func (a *App) webdavRestore(name string) {
	if err := a.checkWritable("WebDAV 恢复"); err != nil {
		a.win.Update(func() { a.notify("只读模式", err.Error()) })
		return
	}
	go func() {
		if err := a.webdavClient().Restore(name); err != nil {
			a.win.Update(func() { a.notify("下载失败", err.Error()) })
			return
		}
		localName := name + "-webdav"
		if err := backup.Restore(localName); err != nil {
			a.win.Update(func() { a.notify("恢复失败", err.Error()) })
			return
		}
		pm, err := loadProfiles()
		if err != nil {
			a.win.Update(func() { a.notify("恢复失败", err.Error()) })
			return
		}
		a.win.Update(func() {
			a.Profiles = pm
			a.reapplyCore()
			a.notify("恢复完成", "已从 WebDAV 备份 "+name+" 恢复")
		})
	}()
}
