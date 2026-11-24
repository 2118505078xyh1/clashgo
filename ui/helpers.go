package ui

import "fmt"

// fmtSscan scans an integer from a string (small local helper).
func fmtSscan(s string, out *int) (int, error) {
	return fmt.Sscan(s, out)
}

func logf(format string, args ...any) {
	fmt.Printf("[clashgo] "+format+"\n", args...)
}
