package ui

import "log"

func (a *App) openEditor(uid string) {
	item := a.Profiles.DB.Find(uid)
	if item == nil {
		return
	}
	content, err := a.Profiles.Content(item)
	if err != nil {
		a.notify("错误", err.Error())
		return
	}
	a.EditorUID = uid
	a.EditorContent = string(content)
	a.EditorOpen = true
}

func (a *App) saveEditor() {
	if err := a.checkWritable("保存配置"); err != nil {
		a.notify("只读模式", err.Error())
		a.EditorOpen = false
		return
	}
	item := a.Profiles.DB.Find(a.EditorUID)
	if item == nil {
		a.EditorOpen = false
		return
	}
	if err := a.Profiles.SaveContent(item, []byte(a.EditorContent)); err != nil {
		a.notify("保存失败", err.Error())
		return
	}
	a.EditorOpen = false
	a.refreshProfileTimer()
	if a.Profiles.DB.Current == a.EditorUID {
		a.reapplyCore()
	}
	log.Printf("profile %s saved", a.EditorUID)
}
