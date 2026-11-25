// Package kernel wraps the proxy core used by clashgo.
//
// The UI talks to the core through one REST API surface (mihomo-compatible:
// /version /configs /proxies /connections /rules /logs /traffic).
// Two backends implement it:
//
//   - BackendSelf: the in-process 自研内核 (pure Go, no external process).
//   - BackendMihomo: the mihomo core running as a child process.
//
// The backend is chosen by config, so switching does not touch the UI.
package kernel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"clashgo/internal/mihomo"
	"clashgo/internal/minikernel"
	"clashgo/internal/validate"
)

// Backend identifies which core implementation is in use.
type Backend string

const (
	// BackendSelf is the in-process 自研内核.
	BackendSelf Backend = "self"
	// BackendMihomo is the external mihomo core.
	BackendMihomo Backend = "mihomo"
)

// Kernel owns the running core.
type Kernel struct {
	mu      sync.Mutex
	backend Backend
	started bool
	// currentYAML is the last successfully applied runtime config.
	currentYAML []byte
	// binaryPath overrides the mihomo executable (used by tests).
	binaryPath string

	// 自研内核 backend
	self         *minikernel.Kernel
	selfAPI      *minikernel.APIServer
	selfListener *minikernel.Listener

	// mihomo backend
	external *mihomo.Core
	workDir  string
}

// New creates a kernel backed by the in-process 自研内核.
//
// Use NewWithBackend to select the external mihomo core instead.
func New() *Kernel { return &Kernel{backend: BackendSelf} }

// NewWithBackend creates a kernel with an explicit backend.
//
// workDir is where the mihomo core keeps its config, geo data and cache;
// it is only used by the external backend.
func NewWithBackend(backend Backend, workDir string) *Kernel {
	return &Kernel{backend: backend, workDir: workDir}
}

// Backend returns the active backend.
func (k *Kernel) Backend() Backend {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.backend
}

// SetBinaryPath overrides the mihomo executable path (used by tests and by
// the installer when the core lives outside the program directory).
func (k *Kernel) SetBinaryPath(path string) {
	k.mu.Lock()
	k.binaryPath = path
	k.mu.Unlock()
	if k.external != nil {
		k.external.SetBinaryPath(path)
	}
}

// Apply parses and applies a runtime YAML config.
func (k *Kernel) Apply(yamlBytes []byte) error {
	return k.ApplyWithController(yamlBytes, "", "")
}

// ApplyWithController applies a config with the external controller address
// and secret overridden.
func (k *Kernel) ApplyWithController(yamlBytes []byte, controller, secret string) error {
	k.mu.Lock()
	backend := k.backend
	workDir := k.workDir
	binaryPath := k.binaryPath
	k.mu.Unlock()

	if backend == BackendMihomo {
		return k.applyExternal(yamlBytes, controller, secret, workDir, binaryPath)
	}
	return k.applySelf(yamlBytes, controller, secret)
}

// applySelf starts the in-process 自研内核.
func (k *Kernel) applySelf(yamlBytes []byte, controller, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	cfg, err := minikernel.ParseConfigBytes(yamlBytes)
	if err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}

	k.stopSelfLocked()

	self, err := minikernel.NewKernelFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("构建内核失败: %w", err)
	}
	lis, err := minikernel.Start(self, cfg.MixedAddr())
	if err != nil {
		return fmt.Errorf("启动内核监听失败: %w", err)
	}
	api := minikernel.NewAPIServer(self, secret)
	api.SetTestURL("http://www.gstatic.com/generate_204")
	if controller != "" {
		if err := api.Start(controller); err != nil {
			lis.Close()
			return fmt.Errorf("启动内核 API 失败: %w", err)
		}
	}

	k.self = self
	k.selfListener = lis
	k.selfAPI = api
	k.currentYAML = append([]byte(nil), yamlBytes...)
	k.started = true
	return nil
}

// applyExternal starts the mihomo core as a child process.
func (k *Kernel) applyExternal(yamlBytes []byte, controller, secret, workDir, binaryPath string) error {
	if workDir == "" {
		workDir = defaultWorkDir()
	}
	core := k.external
	if core == nil {
		core = mihomo.New()
		k.mu.Lock()
		k.external = core
		k.workDir = workDir
		k.mu.Unlock()
	}
	if err := core.Apply(yamlBytes, mihomo.Options{
		BinaryPath: binaryPath,
		WorkDir:    workDir,
		Controller: controller,
		Secret:     secret,
	}); err != nil {
		return err
	}
	k.mu.Lock()
	k.currentYAML = append([]byte(nil), yamlBytes...)
	k.started = true
	k.mu.Unlock()
	return nil
}

// defaultWorkDir 决定 mihomo 工作目录：优先程序同目录的 data/core。
func defaultWorkDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if st, e := os.Stat(filepath.Join(dir, "data")); e == nil && st.IsDir() {
			return filepath.Join(dir, "data", "core")
		}
		return filepath.Join(dir, "core")
	}
	return filepath.Join(os.TempDir(), "clashgo-core")
}

// stopSelfLocked releases the in-process core.
func (k *Kernel) stopSelfLocked() {
	if k.self != nil {
		if k.self.DNS != nil {
			_ = k.self.DNS.Close()
		}
		if k.self.TUN != nil {
			_ = k.self.TUN.Close()
		}
	}
	if k.selfAPI != nil {
		_ = k.selfAPI.Close()
		k.selfAPI = nil
	}
	if k.selfListener != nil {
		_ = k.selfListener.Close()
		k.selfListener = nil
	}
	k.self = nil
}

// ApplyValidated validates a config before replacing the running one.
// If the new config fails validation, the previous config is re-applied.
func (k *Kernel) ApplyValidated(yamlBytes []byte, controller, secret string) error {
	if err := ParseOnly(yamlBytes); err != nil {
		return fmt.Errorf("配置校验失败: %w", err)
	}
	if res := validate.Validate(yamlBytes); !res.Valid {
		return fmt.Errorf("配置语义校验失败: %s", res.Issues[0].Message)
	}
	prev := k.CurrentYAML()
	if err := k.ApplyWithController(yamlBytes, controller, secret); err != nil {
		if len(prev) > 0 {
			_ = k.ApplyWithController(prev, controller, secret)
		}
		return err
	}
	return nil
}

// Stop suspends traffic handling and releases the listeners.
func (k *Kernel) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.started {
		return nil
	}
	if k.external != nil {
		_ = k.external.Stop()
	}
	k.stopSelfLocked()
	k.started = false
	return nil
}

// Suspend / Resume implement the lightweight-mode idle hooks.
func (k *Kernel) Suspend() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.self != nil {
		k.self.SetPaused(true)
	}
}

// Resume resumes the in-process core.
func (k *Kernel) Resume() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.self != nil {
		k.self.SetPaused(false)
	}
}

// Started reports whether a config has been applied.
func (k *Kernel) Started() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.started
}

// Core returns the underlying 自研内核 (for introspection/tests).
// It is nil when the external mihomo backend is active.
func (k *Kernel) Core() *minikernel.Kernel {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.self
}

// CurrentYAML returns a copy of the applied runtime config.
func (k *Kernel) CurrentYAML() []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]byte(nil), k.currentYAML...)
}

// ValidateYAML runs semantic validation and returns all issues (errors+warnings).
func ValidateYAML(yamlBytes []byte) []validate.Issue {
	return validate.Validate(yamlBytes).Issues
}

// ParseOnly validates a config without applying it.
func ParseOnly(yamlBytes []byte) error {
	if len(yamlBytes) == 0 {
		return errors.New("empty config")
	}
	if _, err := minikernel.ParseConfigBytes(yamlBytes); err != nil {
		return err
	}
	return nil
}
