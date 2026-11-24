// Package kernel wraps clashgo's self-developed pure-Go core as an in-process
// library. The core runs in the same binary as the UI: no external sidecar
// executable and no third-party core dependency.
package kernel

import (
	"errors"
	"fmt"
	"sync"

	"clashgo/internal/minikernel"
	"clashgo/internal/validate"
)

// Kernel owns the embedded self-developed core.
type Kernel struct {
	mu      sync.Mutex
	started bool
	// currentYAML is the last successfully applied runtime config.
	currentYAML []byte

	self         *minikernel.Kernel
	selfAPI      *minikernel.APIServer
	selfListener *minikernel.Listener
}

// New creates a kernel backed by the self-developed core.
func New() *Kernel { return &Kernel{} }

// Apply parses and applies a runtime YAML config.
func (k *Kernel) Apply(yamlBytes []byte) error {
	return k.ApplyWithController(yamlBytes, "", "")
}

// ApplyWithController applies a config with the external controller address
// and secret overridden.
func (k *Kernel) ApplyWithController(yamlBytes []byte, controller, secret string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	cfg, err := minikernel.ParseConfigBytes(yamlBytes)
	if err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}

	k.stopLocked()

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

func (k *Kernel) stopLocked() {
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
	k.stopLocked()
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

// Core returns the underlying self-developed kernel (for introspection/tests).
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
