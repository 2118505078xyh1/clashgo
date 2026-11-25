package ui

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"clashgo/internal/autogroup"
	"clashgo/internal/backup"
	"clashgo/internal/batch"
	"clashgo/internal/config"
	"clashgo/internal/controller"
	"clashgo/internal/dnsq"
	"clashgo/internal/enhance"
	"clashgo/internal/guard"
	"clashgo/internal/i18n"
	"clashgo/internal/ipinfo"
	"clashgo/internal/kernel"
	"clashgo/internal/lastgood"
	"clashgo/internal/lightweight"
	"clashgo/internal/nodeprobe"
	"clashgo/internal/notice"
	"clashgo/internal/pac"
	"clashgo/internal/paths"
	"clashgo/internal/portfallback"
	"clashgo/internal/profile"
	"clashgo/internal/runtime"
	"clashgo/internal/snapshot"
	"clashgo/internal/speedtest"
	"clashgo/internal/sysproxy"
	"clashgo/internal/unlock"
	"clashgo/internal/updater"
	"clashgo/internal/version"
	"clashgo/internal/webapi"
	"clashgo/internal/webdav"
)

// App is the whole application's state. It lives for the app's lifetime;
// the view is a pure function of this state.
type App struct {
	win    *mygo.Window
	router *ui.Router

	Settings      *config.Settings
	Profiles      *profile.Manager
	ProfileTimer  *profile.ProfileTimer
	Kernel        *kernel.Kernel
	Client        *controller.Client
	clientMu      sync.RWMutex // guards Client pointer across goroutines
	PAC           *pac.Server
	PortResolver  *portfallback.Resolver
	EffectivePort int // session-only port actually used (fallback may differ)

	// currentClient returns a stable snapshot of the REST client.
	currentClient func() *controller.Client

	// Live data (refreshed in the background).
	Proxies          map[string]config.ProxyView
	Rules            []map[string]any
	Connections      []config.ConnectionView
	Logs             []config.LogView
	DNSRecords       []dnsq.Record
	Version          map[string]any
	Up, Down         int64
	UpRate, DownRate int64

	// UI state
	SelectedPage           string
	SidebarSection         bool
	Search                 string
	ImportURL              string
	ImportName             string
	SelectedProfile        string
	LatencyTesting         bool
	Message                string
	DialogOpen             bool
	HelpOpen               bool // 使用说明 dialog
	DialogTitle            string
	DialogBody             string
	Notices                *notice.Manager
	NoticesExpanded        bool
	ModeMenuOpen           bool
	ExitIP                 *ipinfo.Info
	RuleSortByHits         bool
	ConnGroupByHost        bool
	ConnNetworkFilter      string // "" / "tcp" / "udp" —— 对齐 Verge 的 All/TCP/UDP 筛选
	ConnShowClosed         bool   // 显示已关闭连接
	AutoGroups             []autogroup.Group
	AutoGroupsOpen         bool
	Requests               []config.ConnectionView
	ActiveReqIDs           map[string]int // id -> index in Requests
	NodeIPResults          map[string]nodeprobe.Result
	NodeProbeBusy          bool
	PipelineSteps          []enhance.Step
	PipelineOpen           bool
	SpeedResults           map[string]speedtest.Result
	SpeedTestBusy          bool
	SpeedCancel            context.CancelFunc
	SpeedMu                sync.Mutex
	WebAPIServer           *webapi.Server
	ColorPickerOpen        bool
	ColorL, ColorC, ColorH float64
	CompositionOpen        bool
	CompositionName        string
	CompositionBase        string
	CompositionContrib     string
	ShowRequests           bool
	RuleJumpFilter         string
	ConfigWarnings         []string
	RuntimeConfigOpen      bool
	RuntimeConfigText      string
	LogLevelFilter         string
	LogPaused              bool // 暂停日志追加（对齐 Verge 的暂停按钮）
	LogNewestFirst         bool // 正序/倒序（对齐 Verge 的排序按钮）
	DNSQueryName           string
	DNSQueryResult         string
	delayCancel            context.CancelFunc
	delayGen               uint64
	delayMu                sync.Mutex
	PendingURL             string // subscription import dialog
	ImportDialog           bool
	LogFollow              bool
	Backups                []backup.Info
	WebDAVFiles            []webdav.File
	UnlockItems            []unlock.Item
	UnlockChecking         bool
	RuleTypeFilter         string
	LatestRelease          *updater.Release
	Lightweight            *lightweight.Controller
	Guard                  *guard.Guard
	HideUnavailable        bool
	ProxySortMode          int // 0=default 1=name 2=delay
	busyNodes              map[string]bool
	portText               string
	socksPortText          string
	httpPortText           string
	lightweightText        string
	timeoutText            string
	PACContentText         string
	// profile editor
	EditorOpen    bool
	EditorUID     string
	EditorContent string
	AttachDialog  bool
	AttachParent  string
	BatchImport   bool

	// delay results cache: group/node -> ms
	Delays map[string]int

	// NodesAllDown 记录最近一次体检中是否所有节点都不可用。
	// 只用于界面告警，绝不自动关闭系统代理。
	NodesAllDown  bool
	LastHealthAt  time.Time

	lastUp, lastDown int64
	trafficSince     time.Time
	streamCancel     context.CancelFunc
	// hidden suspends all UI-side polling and rendering while the window is
	// in the tray. The proxy core keeps running.
	hidden atomic.Bool
	// tray is set by main once the tray icon is created.
	Tray *mygo.Tray

	// traffic history (ring of samples for the chart)
	upHistory   []float64
	downHistory []float64
}

// NewApp initializes all backends and starts the kernel.
func NewApp() (*App, error) {
	return newAppWithOptions(false)
}

// newAppWithOptions allows headless/test construction to skip starting the
// 自研内核 core (which is the slow part — needed only by the real GUI app).
func newAppWithOptions(skipCore bool) (*App, error) {
	s, err := config.LoadSettings(configPath())
	if err != nil {
		return nil, err
	}
	// 对齐 Clash Verge：默认启动首页；保留用户显式选择。
	if s.StartPage == "" {
		s.StartPage = "/home"
	}
	pm, err := profile.New()
	if err != nil {
		return nil, err
	}
	if len(pm.DB.Items) == 0 {
		if _, err := pm.CreateLocal("默认配置", profile.DefaultProfile); err != nil {
			return nil, err
		}
	}
	// 内核后端由配置决定：默认 mihomo（Reality/Vision 等细节更成熟），
	// 可切回进程内自研内核。
	backend := kernel.BackendSelf
	if s.CoreBackend == string(kernel.BackendMihomo) {
		backend = kernel.BackendMihomo
	}
	k := kernel.NewWithBackend(backend, filepath.Join(paths.Home, "core"))
	client := controller.New(s.ExternalController, s.Secret)

	a := &App{
		router:    ui.NewRouter(s.StartPage),
		Notices:   notice.New(50),
		Settings:  s,
		Profiles:  pm,
		Kernel:    k,
		Client:    client,
		Proxies:   map[string]config.ProxyView{},
		Delays:    map[string]int{},
		LogFollow: true,
	}
	a.PAC = pac.New(s.PACContent)
	if s.EnablePAC {
		_, _ = a.PAC.Start()
	}
	a.UnlockItems = unlock.PendingItems()
	a.busyNodes = map[string]bool{}
	a.ActiveReqIDs = map[string]int{}
	a.NodeIPResults = map[string]nodeprobe.Result{}
	a.SpeedResults = map[string]speedtest.Result{}
	a.Lightweight = lightweight.New(s.LightweightMinutes,
		func() { a.Kernel.Suspend() },
		func() { a.Kernel.Resume() },
	)
	a.Lightweight.SetEnabled(s.EnableLightweight)
	if !skipCore {
		a.refreshGuard()
	}
	a.portText = fmt.Sprintf("%d", s.MixedPort)
	a.socksPortText = fmt.Sprintf("%d", s.SocksPort)
	a.httpPortText = fmt.Sprintf("%d", s.HTTPPort)
	a.lightweightText = fmt.Sprintf("%d", s.LightweightMinutes)
	a.timeoutText = fmt.Sprintf("%d", s.LatencyTimeout)
	a.PACContentText = s.PACContent
	if a.PACContentText == "" {
		a.PACContentText = pac.DefaultPAC
	}
	a.currentClient = func() *controller.Client {
		a.clientMu.RLock()
		defer a.clientMu.RUnlock()
		return a.Client
	}
	if !skipCore {
		if err := a.applyCurrentProfile(); err != nil {
			log.Printf("core start failed: %v", err)
			a.Message = "内核启动失败：" + err.Error()
		}
	}
	return a, nil
}

// applyCurrentProfile generates and applies runtime config from the
// current profile, then (re)creates the REST client.
func (a *App) applyCurrentProfile() error {
	item := a.Profiles.DB.CurrentItem()
	var content []byte
	if item == nil {
		// 删除全部配置后仍用内置默认配置运行，避免界面空壳并让“删除”看起来失效。
		content = []byte(profile.DefaultProfile)
	} else if item.Type != config.ProfileComposition {
		var err error
		content, err = a.Profiles.Content(item)
		if err != nil {
			return err
		}
		// 订阅刷新失败时可能把 HTML 错误页写进配置，不能直接喂给内核；
		// 此时临时使用内置默认配置，保证界面仍可使用。
		if verr := profile.ValidateConfig(content); verr != nil {
			log.Printf("active profile %s is not a Clash config: %v; using default profile", item.UID, verr)
			a.Message = "当前配置不是有效的 Clash 配置，已临时使用内置默认配置。请重新导入订阅。"
			a.Notices.Push(notice.ConfigInvalid, a.Message, notice.Warning)
			content = []byte(profile.DefaultProfile)
		}
	}
	// Session-only port fallback: if the user's port is occupied, use the
	// next free port for this session only (never persist to settings).
	if a.PortResolver == nil {
		a.PortResolver = portfallback.New(
			a.Settings.SocksPort, a.Settings.HTTPPort,
			9097, // external controller
		)
	}
	resolved, changed := a.PortResolver.Resolve(a.Settings.MixedPort)
	a.EffectivePort = resolved
	sessionSettings := *a.Settings
	sessionSettings.MixedPort = resolved
	if changed {
		log.Printf("mixed port %d occupied; using session fallback %d", a.Settings.MixedPort, resolved)
	}
	// Snapshot the current on-disk files before touching runtime config; on a
	// terminal failure we restore so the next launch still has a good config.
	snap := snapshot.Capture(runtimePath(), configPath())
	data, err := runtime.Generate(content, &sessionSettings, item, a.Profiles.DB, runtimePath())
	a.PipelineSteps = runtime.LastSteps
	if err != nil {
		return err
	}
	// Collect semantic warnings (e.g. dangling group references) and surface
	// them in the notification panel instead of silently discarding.
	var warnings []string
	for _, iss := range kernel.ValidateYAML(data) {
		if iss.Level == "warning" {
			warnings = append(warnings, iss.Message)
		}
	}
	a.ConfigWarnings = warnings
	if len(warnings) > 0 {
		a.Notices.Push("config::warnings", "配置校验警告（"+itoaLocal(len(warnings))+" 条）", notice.Warning)
	}
	if err := a.Kernel.ApplyValidated(data, a.Settings.ExternalController, a.Settings.Secret); err != nil {
		// TUN degradation: TUN may fail on unprivileged Windows. Retry once
		// with TUN disabled so the HTTP/SOCKS proxy still works (idea from
		// a reference client: "TUN is not a required run condition").
		if sessionSettings.EnableTUN {
			log.Printf("config with TUN failed (%v); retrying with TUN disabled", err)
			sessionSettings.EnableTUN = false
			data, genErr := runtime.Generate(content, &sessionSettings, item, a.Profiles.DB, runtimePath())
			if genErr == nil {
				if retryErr := a.Kernel.ApplyValidated(data, a.Settings.ExternalController, a.Settings.Secret); retryErr == nil {
					a.Message = "TUN 模式启动失败，已降级为仅代理模式（可在设置重试）"
					a.clientMu.Lock()
					a.Client = controller.New(a.Settings.ExternalController, a.Settings.Secret)
					a.clientMu.Unlock()
					return nil
				}
			}
		}
		// Terminal failure: restore the previous runtime/settings from snapshot.
		_ = snap.Restore()
		return err
	}
	a.clientMu.Lock()
	a.Client = controller.New(a.Settings.ExternalController, a.Settings.Secret)
	a.clientMu.Unlock()
	// Remember this as the last known-good config for crash recovery.
	_ = lastgood.Save(paths.Home, data)
	return nil
}

// SetWindow binds the window and starts background polling and streams.
func (a *App) SetWindow(win *mygo.Window) {
	a.win = win
	go a.pollLoop()
	go a.streamLoop()
	a.startAutoUpdateCheck()
	a.startSSIDAutomation()
	a.startWebAPI()
	a.startProfileTimer()
}

// SetHidden suspends UI work while the window lives in the tray. It does not
// touch the proxy core, so connections and system proxy stay active.
func (a *App) SetHidden(h bool) {
	if h == a.hidden.Swap(h) {
		return
	}
	if !h && a.win != nil {
		a.win.Invalidate()
	}
}

func (a *App) IsHidden() bool { return a.hidden.Load() }

// streamLoop keeps traffic, log and connection websocket streams alive.
// Data arrives on the wire and is handed to the UI thread in batches.
func (a *App) streamLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.streamCancel = cancel

	client := a.currentClient

	// Traffic arrives at high frequency; accumulate into a local counter and
	// flush to the UI at most every 100ms to avoid repaint storms.
	trafficAcc := struct {
		sync.Mutex
		up, down int64
	}{}
	trafficCoalescer := batch.New(100*time.Millisecond, func(any) {
		trafficAcc.Lock()
		up, down := trafficAcc.up, trafficAcc.down
		trafficAcc.up, trafficAcc.down = 0, 0
		trafficAcc.Unlock()
		if up == 0 && down == 0 {
			return
		}
		// 累计值由 REST /stats 读取绝对值；这里只累加速率增量。
		a.win.Update(func() {
			a.lastUp += up
			a.lastDown += down
		})
	})
	defer trafficCoalescer.Stop()

	go controller.ReconnectStream(ctx, "traffic", func(c context.Context) error {
		return client().StreamTraffic(c, func(s controller.TrafficSample) {
			if (s.Up > 0 || s.Down > 0) && a.Lightweight != nil {
				a.Lightweight.Activity()
			}
			// 隐藏到托盘时也要累计流量，否则"已转发"和实时流量在恢复后断层。
			trafficAcc.Lock()
			trafficAcc.up += s.Up
			trafficAcc.down += s.Down
			trafficAcc.Unlock()
			trafficCoalescer.Submit(nil)
		})
	})
	go controller.ReconnectStream(ctx, "logs", func(c context.Context) error {
		return client().StreamLogs(c, func(f controller.LogFrame) {
			if a.LogPaused {
				return
			}
			// 隐藏时也收集日志（日志是流式的，丢弃后无法恢复）。
			a.win.Update(func() {
				a.Logs = append(a.Logs, config.LogView{
					Type: f.Type, Time: f.Time, Payload: f.Payload,
				})
				if rec, ok := dnsq.Parse(f.Time, f.Payload); ok {
					a.DNSRecords = append(a.DNSRecords, rec)
					if len(a.DNSRecords) > 500 {
						a.DNSRecords = a.DNSRecords[len(a.DNSRecords)-500:]
					}
				}
				if len(a.Logs) > 2000 {
					a.Logs = a.Logs[len(a.Logs)-2000:]
				}
			})
		})
	})
	go controller.ReconnectStream(ctx, "connections", func(c context.Context) error {
		return client().StreamConnections(c, func(f controller.ConnectionFrame) {
			// 隐藏时也更新连接数据，恢复窗口后立即显示当前状态。
			a.win.Update(func() {
				a.Connections = f.Connections
				for _, conn := range f.Connections {
					if _, seen := a.ActiveReqIDs[conn.ID]; seen {
						continue
					}
					a.ActiveReqIDs[conn.ID] = len(a.Requests)
					a.Requests = append(a.Requests, conn)
				}
				if len(a.Requests) > 2000 {
					trimmed := a.Requests[len(a.Requests)-2000:]
					a.Requests = trimmed
					a.ActiveReqIDs = map[string]int{}
					for i, r := range trimmed {
						a.ActiveReqIDs[r.ID] = i
					}
				}
			})
		})
	})
}

// pollLoop refreshes live data from 自研内核's REST API twice a second and
// pushes changes to the UI thread via win.Update.
func (a *App) pollLoop() {
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		// Lightweight mode: 窗口可见时用户正在使用界面，算作活动，
		// 避免内核被挂起后因无流量而无法恢复（挂起会拒绝新连接，
		// 导致所有网站测试失败、流量统计归零）。
		if a.Lightweight != nil {
			if !a.IsHidden() {
				a.Lightweight.Activity()
			}
			a.Lightweight.Tick()
		}
		if a.IsHidden() {
			continue // no REST polling or repaint work while in the tray
		}
		cli := a.currentClient()
		proxies, _ := cli.Proxies()
		rules, _ := cli.Rules()
		version, _ := cli.Version()
		// 累计流量从内核 REST 读取绝对值（WS 增量在重启后会丢失历史）。
		stats, _ := cli.Stats()

		a.win.Update(func() {
			a.Proxies = proxies
			a.Rules = rules
			if stats != nil {
				if up, ok := stats["upload"].(float64); ok {
					a.Up = int64(up)
				}
				if down, ok := stats["download"].(float64); ok {
					a.Down = int64(down)
				}
			}
			// Connections come from the WebSocket stream (no REST poll needed).
			if version != nil {
				a.Version = version
			}
			// Traffic websocket accumulates lastUp/lastDown; turn 700ms worth
			// into a per-second rate estimate.
			if a.trafficSince.IsZero() {
				a.trafficSince = time.Now()
			}
			elapsed := time.Since(a.trafficSince).Seconds()
			if elapsed >= 0.5 {
				a.DownRate = int64(float64(a.lastDown) / elapsed)
				a.UpRate = int64(float64(a.lastUp) / elapsed)
				a.lastUp, a.lastDown = 0, 0
				a.trafficSince = time.Now()
				const maxHistory = 90
				a.upHistory = append(a.upHistory, float64(a.UpRate))
				a.downHistory = append(a.downHistory, float64(a.DownRate))
				if len(a.upHistory) > maxHistory {
					a.upHistory = a.upHistory[1:]
					a.downHistory = a.downHistory[1:]
				}
			}
		})
	}
}

// View builds the whole window: sidebar + routed page.
func (a *App) View(c *ui.Context) {
	// Apply the fixed dark Clash Party palette, independent of OS appearance.
	accent := a.Settings.PrimaryColor
	applyRefinedTheme(c, accent, a.Settings.ThemeMode)

	// One selectable scope for all static text on every page. Text inside
	// controls (buttons, inputs, editors) keeps its own interaction.
	ui.Row(c).Fill().AlignItems(ui.Stretch).Selectable().Children(func() {
		a.sidebar(c)
		ui.Column(c).Grow(1).Children(func() {
			a.router.View(c, func(r *ui.Route) {
				switch {
				case r.Match("/home"):
					r.Title(a.tr("home"))
					a.pageHome(c)
				case r.Match("/proxies"):
					r.Title(a.tr("proxies"))
					a.pageProxies(c)
				case r.Match("/profiles"):
					r.Title("订阅")
					a.pageProfiles(c)
				case r.Match("/rules"):
					r.Title("规则")
					a.pageRules(c)
				case r.Match("/connections"):
					r.Title("连接")
					a.pageConnections(c)
				case r.Match("/logs"):
					r.Title("日志")
					a.pageLogs(c)
				case r.Match("/unlock"):
					r.Title("测试")
					a.pageUnlock(c)
				case r.Match("/dns"):
					r.Title("DNS 查询")
					a.pageDNS(c)
				case r.Match("/requests"):
					r.Title("请求记录")
					a.pageRequests(c)
				case r.Match("/settings"):
					r.Title("设置")
					a.pageSettings(c)
				default:
					r.Title("首页")
					a.pageHome(c)
				}
			})
		})
	})

	// Overlay dialogs.
	a.overlays(c)
	a.helpOverlay(c)
}

func (a *App) tr(id string) string {
	return i18n.T(i18n.Lang(a.Settings.Language), id)
}

// trs translates a Chinese UI string directly (used for the many labels that
// don't have a separate msgid).
func (a *App) trs(s string) string {
	return i18n.TByZH(i18n.Lang(a.Settings.Language), s)
}

func (a *App) sidebar(c *ui.Context) {
	t := c.Theme()
	page := a.router.Path()
	active := func(p string) bool { return page == p }

	ui.Column(c).Width(220).Padding(12, 10).Gap(6).Background(t.Background).Children(func() {
		// 顶部：Logo + 应用名（Clash Verge 风格）
		ui.Row(c).Gap(8).AlignItems(ui.Center).Padding(4, 6, 14, 6).Children(func() {
			ui.Image(c, logoBitmap).Size(28, 28)
			ui.Column(c).Gap(0).Children(func() {
				text(c, "ClashGo").FontSize(15).Bold()
				text(c, "v"+version.App).FontSize(10).TextColor(t.TextMuted)
			})
		})

		// 8 项标准导航（对齐 Clash Verge：首页/代理/订阅/连接/规则/日志/测试/设置）
		for _, nav := range []struct {
			path, label string
			icon        *ui.SVG
		}{
			{"/home", "首页", iconHome},
			{"/proxies", "代理", iconProxy},
			{"/profiles", "订阅", iconProfile},
			{"/connections", "连接", iconConnections},
			{"/rules", "规则", iconRules},
			{"/logs", "日志", iconLogs},
			{"/unlock", "测试", iconUnlock},
			{"/settings", "设置", iconSettings},
		} {
			navPath, navLabel, navIcon := nav.path, nav.label, nav.icon
			// 默认路由（空路径）视为首页高亮
			sel := active(navPath) || (navPath == "/home" && (page == "" || page == "/"))
			navRow(c, navIcon, navLabel, sel, func() { a.router.Push(navPath) })
		}

		ui.Spacer(c).Grow(1)

		// 底部实时流量（Clash Verge 的 LayoutTraffic）
		ui.Column(c).Gap(4).Padding(10).Radius(10).Background(t.Surface).Children(func() {
			ui.Box(c).Height(46).FillWidth().Radius(6).Draw(func(p *ui.Painter, r ui.Rect) {
				drawTrafficChart(p, r, a.upHistory, a.downHistory, t)
			})
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				text(c, "↑").FontSize(11).TextColor(t.Accent)
				text(c, humanRate(a.UpRate)).FontSize(11).TextColor(t.Accent).Grow(1)
			})
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				text(c, "↓").FontSize(11).TextColor(t.Success)
				text(c, humanRate(a.DownRate)).FontSize(11).TextColor(t.Success).Grow(1)
			})
		})
	})
}

func (a *App) notify(title, body string) {
	level := notice.Info
	switch {
	case containsFoldAny(title, "失败", "错误", "error", "failed"):
		level = notice.Error
	case containsFoldAny(title, "成功", "完成", "ok"):
		level = notice.Success
	case containsFoldAny(title, "警告", "warning"):
		level = notice.Warning
	}
	a.Notices.Push("ui::"+title, body, level)
	// Only errors/warnings interrupt with a modal; info/success are recorded
	// silently and shown in the notification panel.
	if level == notice.Error || level == notice.Warning {
		a.DialogTitle, a.DialogBody, a.DialogOpen = title, body, true
	}
}

func containsFoldAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if containsFold(s, sub) {
			return true
		}
	}
	return false
}

func (a *App) mustSaveSettings() {
	if err := config.SaveSettings(configPath(), a.Settings); err != nil {
		log.Printf("save settings: %v", err)
	}
}

func (a *App) reapplyCore() {
	if err := a.applyCurrentProfile(); err != nil {
		a.notify("错误", err.Error())
	}
}

func (a *App) applySystemProxy() {
	// Drain the guard BEFORE writing, so a pending guard write cannot race
	// with our explicit set and resurrect a proxy we just disabled.
	if a.Guard != nil {
		a.Guard.Stop()
		a.Guard = nil
	}
	port := a.Settings.MixedPort
	if a.EffectivePort > 0 {
		port = a.EffectivePort
	}
	server := fmt.Sprintf("127.0.0.1:%d", port)
	setErr := sysproxy.Set(a.Settings.EnableSystemProxy, server, a.Settings.ProxyBypass)
	if setErr != nil {
		a.notify("系统代理", "设置失败："+setErr.Error())
	}
	a.mustSaveSettings()
	// Only re-arm the guard after a successful write (never point the guard at
	// a target we failed to apply — a reference GUI's "never guard a failed target").
	if setErr == nil && a.Settings.EnableSystemProxy {
		a.refreshGuard()
		// 打开系统代理后立即体检一次：节点全挂时首页会提示，
		// 但绝不会自动关闭系统代理（避免在用户不知情时改变整机网络走向）。
		go func() {
			a.checkNodesHealth()
			if a.win != nil {
				a.win.Update(func() {})
			}
		}()
	}
}

func (a *App) openSubscriptionDialog() {
	a.ImportDialog = true
	a.ImportName = ""
	a.PendingURL = ""
	a.BatchImport = false
}

func (a *App) doImport() {
	if err := a.checkWritable("导入订阅"); err != nil {
		a.notify("只读模式", err.Error())
		return
	}
	url := strings.TrimSpace(a.PendingURL)
	if url == "" {
		a.notify("错误", "请输入订阅地址")
		return
	}
	name := strings.TrimSpace(a.ImportName)
	if name == "" {
		name = "订阅 " + time.Now().Format("01-02 15:04")
	}
	if a.BatchImport {
		count, errs := a.Profiles.ImportBatch(name, url, &config.PrfOption{TimeoutSeconds: 30})
		a.ImportDialog = false
		a.reapplyCore()
		msg := "成功导入 " + itoaLocal(count) + " 个订阅"
		if len(errs) > 0 {
			msg += "\n" + strings.Join(errs[:minInt(len(errs), 5)], "\n")
		}
		a.notify("批量导入完成", msg)
		return
	}
	_, err := a.Profiles.ImportRemote(name, url, &config.PrfOption{TimeoutSeconds: 30})
	if err != nil {
		a.notify("导入失败", err.Error())
		return
	}
	a.ImportDialog = false
	a.refreshProfileTimer()
	a.reapplyCore()
	a.notify("导入成功", "已添加订阅："+name)
}

func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
