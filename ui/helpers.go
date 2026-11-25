package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"clashgo/internal/paths"
)

// fmtSscan scans an integer from a string (small local helper).
func fmtSscan(s string, out *int) (int, error) {
	return fmt.Sscan(s, out)
}

var (
	diagMu   sync.Mutex
	diagFile *os.File
)

// logf 写一条诊断日志。
//
// GUI 程序没有控制台，stdout 会丢失，所以日志写进数据目录的 logs/diag.log，
// 排查问题时可以直接看这个文件。
func logf(format string, args ...any) {
	line := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...) + "\n"

	diagMu.Lock()
	defer diagMu.Unlock()
	if diagFile == nil {
		dir := paths.Logs
		if dir == "" {
			dir = os.TempDir()
		} else {
			_ = os.MkdirAll(dir, 0o755)
		}
		f, err := os.OpenFile(filepath.Join(dir, "diag.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Print(line)
			return
		}
		diagFile = f
	}
	_, _ = diagFile.WriteString(line)
}
