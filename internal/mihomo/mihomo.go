// Package mihomo runs the mihomo core as a child process and exposes it
// through the same REST API surface the UI already speaks.
//
// Why an external core instead of the in-process 自研内核:
// mihomo 的 Reality / XTLS Vision / uTLS 指纹实现经过多年实战检验，
// 自研内核在这些细节上仍有差距（节点可用但握手后被服务端重置）。
// UI、业务逻辑和 REST 协议保持不变，只替换最底层的出站实现。
package mihomo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"clashgo/internal/hidewin"
)

// Core is a running mihomo instance.
type Core struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	workDir    string
	config     string
	yaml       []byte
	started    bool
	binary     string
	logPath    string
	controller string
}

// Options configures a core instance.
type Options struct {
	// BinaryPath is the mihomo executable. Empty means auto-detect.
	BinaryPath string
	// WorkDir holds the generated config, the geo data files and the cache.
	WorkDir string
	// Controller is the external controller address, e.g. "127.0.0.1:9097".
	Controller string
	// Secret is the external controller secret.
	Secret string
}

// SetBinaryPath overrides the mihomo executable path.
func (c *Core) SetBinaryPath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binary = path
}

// New creates a core manager without starting anything.
func New() *Core { return &Core{} }

// Apply writes the config and starts (or restarts) the core.
//
// The generated YAML already carries mixed-port / external-controller /
// secret, so the core is started with exactly that file and nothing else
// is injected — the UI's runtime config stays the single source of truth.
func (c *Core) Apply(yamlBytes []byte, opts Options) error {
	if len(yamlBytes) == 0 {
		return errors.New("mihomo: empty config")
	}
	c.mu.Lock()
	explicit := opts.BinaryPath
	if explicit == "" {
		explicit = c.binary
	}
	c.mu.Unlock()
	bin, err := resolveBinary(explicit)
	if err != nil {
		return err
	}
	workDir := opts.WorkDir
	if workDir == "" {
		return errors.New("mihomo: empty work dir")
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("mihomo: create work dir: %w", err)
	}
	cfgPath := filepath.Join(workDir, "config.yaml")
	if err := os.WriteFile(cfgPath, yamlBytes, 0o644); err != nil {
		return fmt.Errorf("mihomo: write config: %w", err)
	}
	// 复用已有的 geo 数据文件，避免首次运行重复下载。
	seedGeoData(workDir)

	c.mu.Lock()
	c.stopLocked()
	c.mu.Unlock()

	// 清理上一次异常退出（被强杀 / 崩溃）遗留的孤儿内核进程：
	// 它们会占住端口，导致新内核起不来。
	killOrphans(bin, opts.Controller, workDir)

	// 隐藏控制台窗口：mihomo 是控制台程序，直接启动会弹黑框。
	cmd := hidewin.CommandNoConsole(bin, "-d", workDir, "-f", cfgPath)
	cmd.Dir = workDir
	// 把内核输出写入文件，而不是管道：管道会让子进程保留控制台句柄。
	logPath := filepath.Join(workDir, "core.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logFile = nil
	}
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		defer logFile.Close()
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("mihomo: start: %w", err)
	}

	c.mu.Lock()
	c.cmd = cmd
	c.workDir = workDir
	c.config = cfgPath
	c.yaml = append([]byte(nil), yamlBytes...)
	c.started = true
	c.logPath = logPath
	c.controller = opts.Controller
	c.mu.Unlock()

	// 等待控制端口就绪，避免 UI 立刻发请求时连接被拒。
	// 首次运行可能需要下载 GeoSite/MMDB，给足时间。
	if err := waitController(opts.Controller, opts.Secret, 90*time.Second); err != nil {
		out := c.Logs()
		c.Stop()
		if out != "" {
			return fmt.Errorf("%w\n内核输出:\n%s", err, out)
		}
		return err
	}
	return nil
}

// Logs returns the tail of the captured core output.
func (c *Core) Logs() string {
	c.mu.Lock()
	path := c.logPath
	c.mu.Unlock()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// 只保留末尾，避免把整个日志塞进错误信息。
	s := string(b)
	if len(s) > 4000 {
		s = s[len(s)-4000:]
	}
	return s
}

// Stop terminates the core process.
func (c *Core) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		return nil
	}
	c.stopLocked()
	return nil
}

func (c *Core) stopLocked() {
	if c.cmd == nil || c.cmd.Process == nil {
		c.started = false
		return
	}
	// 先请求正常退出，超时再强杀，避免留下孤儿进程占住端口。
	cmd := c.cmd
	c.cmd = nil
	c.started = false

	done := make(chan struct{})
	go func() {
		_ = cmd.Process.Kill()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	_ = cmd.Wait()
	// 进程退出后端口可能还在 TIME_WAIT 或尚未释放，
	// 等一下再启动新内核，否则新进程会报 "bind: address already in use"。
	waitPortFree(c.controller, 5*time.Second)
}

// Started reports whether the core process is running.
func (c *Core) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

// CurrentYAML returns the config the core was started with.
func (c *Core) CurrentYAML() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.yaml...)
}

// waitController 轮询外部控制端口，直到能拿到 /version 响应。
func waitController(addr, secret string, timeout time.Duration) error {
	if addr == "" {
		return nil
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	base := strings.TrimRight(addr, "/")
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, base+"/version", nil)
		if err != nil {
			return err
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("mihomo: controller returned HTTP %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("mihomo: controller not ready: %w", lastErr)
}

// resolveBinary 定位 mihomo 可执行文件。
//
// 查找顺序：
//  1. 显式指定的路径
//  2. 程序同目录下的 mihomo.exe（绿色版 / 安装包内嵌）
//  3. 数据目录下的 core/mihomo.exe（下载后放置的位置）
//  4. PATH 中的 mihomo
func resolveBinary(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("mihomo: binary not found: %s", explicit)
	}
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "mihomo.exe"),
			filepath.Join(dir, "core", "mihomo.exe"),
		)
	}
	if home := os.Getenv("CLASHGO_DATA_DIR"); home != "" {
		candidates = append(candidates, filepath.Join(home, "core", "mihomo.exe"))
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	if p, err := exec.LookPath("mihomo"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("mihomo.exe"); err == nil {
		return p, nil
	}
	return "", errors.New("mihomo: 未找到 mihomo 可执行文件（请放到程序目录或 core/ 子目录）")
}

// seedGeoData 把已有的 geo 数据文件复制到工作目录。
//
// mihomo 首次运行会下载 GeoSite.dat / geoip.dat / Country.mmdb（几十 MB）。
// 如果本机其他客户端已经有这些文件，直接复用能省掉一次下载。
func seedGeoData(workDir string) {
	names := []string{"GeoSite.dat", "geosite.dat", "geoip.dat", "GeoIP.dat", "country.mmdb", "Country.mmdb"}
	sources := []string{}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		sources = append(sources,
			filepath.Join(dir, "data", "core"),
			filepath.Join(dir, "core"),
			filepath.Join(dir, "data"),
		)
	}
	if home := os.Getenv("CLASHGO_DATA_DIR"); home != "" {
		sources = append(sources, filepath.Join(home, "core"), home)
	}
	// mihomo 官方配置目录（用户可能已经手动放好 geo 文件）。
	if cfgDir, err := os.UserConfigDir(); err == nil {
		sources = append(sources, filepath.Join(cfgDir, "mihomo"))
	}
	// 用户数据目录（profile 等）。
	if home, err := os.UserHomeDir(); err == nil {
		sources = append(sources, filepath.Join(home, ".config", "mihomo"))
	}
	for _, src := range sources {
		for _, name := range names {
			from := filepath.Join(src, name)
			to := filepath.Join(workDir, name)
			if _, err := os.Stat(to); err == nil {
				continue // 已存在，不覆盖
			}
			if st, err := os.Stat(from); err != nil || st.IsDir() {
				continue
			}
			if err := copyFile(from, to); err == nil {
				return
			}
		}
	}
}

// copyFile 复制一个小文件（geo 数据最大几十 MB）。
func copyFile(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(to)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// waitPortFree 等待控制端口释放。
//
// 内核进程退出后，监听套接字的释放可能有短暂延迟（尤其 Windows 上
// 处于 TIME_WAIT 的连接）。不等待就启动新内核会报 "bind: address
// already in use"，导致新内核起不来、旧配置仍在生效。
func waitPortFree(addr string, timeout time.Duration) {
	if addr == "" {
		return
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, portStr))
		if err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ControllerPort 从 external-controller 地址里取出端口号。
func ControllerPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var p int
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return 0
		}
		p = p*10 + int(c-'0')
	}
	return p
}

// WaitReady 阻塞等待核心就绪，供启动流程使用。
func WaitReady(ctx context.Context, addr, secret string) error {
	return waitController(addr, secret, 20*time.Second)
}
