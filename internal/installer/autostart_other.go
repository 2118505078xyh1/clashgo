//go:build !windows

package installer

import "fmt"

func AddAutoStart(exePath string) error { return fmt.Errorf("Windows only") }
func RemoveAutoStart() error            { return fmt.Errorf("Windows only") }
func quotePS(s string) string           { return s }
