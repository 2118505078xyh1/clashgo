package kernel

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"clashgo/internal/config"
	"clashgo/internal/controller"
	"clashgo/internal/profile"
	"clashgo/internal/runtime"
)

// TestMihomoBackendStarts 用真实的 mihomo 可执行文件验证外部后端。
// 环境变量 CLASHGO_TEST_MIHOMO 指向 mihomo 可执行文件时才会运行。
func TestMihomoBackendStarts(t *testing.T) {
	bin := os.Getenv("CLASHGO_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set CLASHGO_TEST_MIHOMO to run this test")
	}
	work := t.TempDir()

	s := config.DefaultSettings()
	s.ExternalController = "127.0.0.1:29297"
	s.MixedPort = 27997
	s.Secret = ""

	k := NewWithBackend(BackendMihomo, work)
	k.SetBinaryPath(bin)
	data, err := runtime.Generate([]byte(profile.DefaultProfile), s, nil, nil, filepath.Join(work, "runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.ApplyWithController(data, s.ExternalController, s.Secret); err != nil {
		t.Fatalf("apply: %v", err)
	}
	defer k.Stop()
	if !k.Started() {
		t.Fatal("kernel not started")
	}

	cli := controller.New(s.ExternalController, s.Secret)
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if v, err := cli.Version(); err == nil {
			if v == nil {
				t.Fatal("nil version")
			}
			return
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("controller not ready: %v", lastErr)
}
