package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/egoist/mygo"
)

// exportConnections writes the current connection list to a text file chosen
// via the OS save dialog.
func (a *App) exportConnections() {
	path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
		Title: "导出连接", DefaultPath: "connections.txt",
		Filters: []mygo.FileFilter{{Name: "Text", Extensions: []string{"txt"}}},
		Parent:  a.win,
	})
	if err != nil || path == "" {
		return
	}
	var b strings.Builder
	b.WriteString("# ClashGo Connections Export\n")
	fmt.Fprintf(&b, "# %d connections\n\n", len(a.Connections))
	for _, c := range a.Connections {
		fmt.Fprintf(&b, "%s  %s  %s  %s → %s  %s ↓\n",
			c.Host, strings.ToUpper(c.Network), c.Rule, c.RulePayload, strings.Join(c.Chain, " → "), humanBytes(c.Download))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		a.notify("导出失败", err.Error())
	} else {
		a.notify("导出成功", "连接列表已保存")
	}
}

// exportLogs writes the current logs to a text file.
func (a *App) exportLogs() {
	path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
		Title: "导出日志", DefaultPath: "clashgo-logs.txt",
		Filters: []mygo.FileFilter{{Name: "Text", Extensions: []string{"txt"}}},
		Parent:  a.win,
	})
	if err != nil || path == "" {
		return
	}
	var b strings.Builder
	for _, l := range a.Logs {
		fmt.Fprintf(&b, "%s [%s] %s\n", l.Time, l.Type, l.Payload)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		a.notify("导出失败", err.Error())
	} else {
		a.notify("导出成功", "日志已保存")
	}
}
