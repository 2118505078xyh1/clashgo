package ui

import "fmt"

func (a *App) checkWritable(op string) error {
	if a.Settings.ReadOnly {
		return fmt.Errorf("只读模式，禁止操作：%s", op)
	}
	return nil
}
