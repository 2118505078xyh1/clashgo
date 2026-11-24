package minikernel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"clashgo/internal/ws"

	"clashgo/internal/version"
)

// LogEntry 是一条日志，广播给 /logs WebSocket 订阅者。
type LogEntry struct {
	Type    string `json:"type"`
	Time    string `json:"time"`
	Payload string `json:"payload"`
}

// APIServer 提供 Clash 兼容的 REST + WebSocket 控制接口。
type APIServer struct {
	k       *Kernel
	secret  string
	srv     *http.Server
	testURL string

	mu      sync.RWMutex
	logSubs map[chan LogEntry]struct{}

	upTemp, downTemp         atomic.Int64
	upRate, downRate         atomic.Int64
	lastUpload, lastDownload int64

	addr string // 实际监听地址（端口 0 时由系统分配）
}

// NewAPIServer 创建 API 服务。secret 为空则不校验。
func NewAPIServer(k *Kernel, secret string) *APIServer {
	s := &APIServer{
		k:       k,
		secret:  secret,
		testURL: "http://www.gstatic.com/generate_204",
		logSubs: map[chan LogEntry]struct{}{},
	}
	// 注册内核日志回调：内核的关键事件广播给 /logs 订阅者。
	k.SetLogSink(func(typ, payload string) { s.Log(typ, payload) })
	return s
}

// SetTestURL 设置延迟测试的探测地址。
func (s *APIServer) SetTestURL(u string) {
	if u != "" {
		s.testURL = u
	}
}

// Start 在 addr 上启动 HTTP 服务（异步）。
func (s *APIServer) Start(addr string) error {
	mux := http.NewServeMux()
	s.routes(mux)
	s.srv = &http.Server{Addr: addr, Handler: s.auth(mux), ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.addr = ln.Addr().String()
	go func() { _ = s.srv.Serve(ln) }()
	go s.rateLoop()
	return nil
}

// Close 关闭 API 服务。
func (s *APIServer) Close() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func (s *APIServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.secret != "" && r.Header.Get("Authorization") != "Bearer "+s.secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// handleStats 返回内核累计流量（供 UI 读取，避免依赖 WS 增量累加导致重启后归零）。
func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"upload":   s.k.uploadTotal.Load(),
		"download": s.k.downloadTotal.Load(),
		"active":   s.k.activeConns.Load(),
	})
}

func (s *APIServer) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /stats", s.handleStats)
	mux.HandleFunc("GET /configs", s.handleConfigs)
	mux.HandleFunc("PATCH /configs", s.handlePatchConfigs)
	mux.HandleFunc("PUT /configs", s.handleReloadConfig)
	mux.HandleFunc("GET /proxies", s.handleProxies)
	mux.HandleFunc("PUT /proxies/{name}", s.handleSelectProxy)
	mux.HandleFunc("GET /proxies/{name}/delay", s.handleProxyDelay)
	mux.HandleFunc("GET /group/{name}/delay", s.handleGroupDelay)
	mux.HandleFunc("GET /rules", s.handleRules)
	mux.HandleFunc("DELETE /connections", s.handleCloseAll)
	mux.HandleFunc("DELETE /connections/{id}", s.handleCloseConn)
	mux.HandleFunc("GET /dns/query", s.handleDNSQuery)
	mux.HandleFunc("GET /traffic", s.handleTrafficWS)
	mux.HandleFunc("GET /logs", s.handleLogsWS)
	// UI 的 StreamConnections 订阅 "/connections"（WebSocket），
	// 而 REST 也用同一路径；用 Upgrade 头在同一个 handler 里分流。
	mux.HandleFunc("GET /connections", s.handleConnectionsAny)
}

func (s *APIServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"version": version.App, // 自研内核：内核版本 = 软件版本
		"mode":    s.k.Mode,
	})
}

func (s *APIServer) handleConfigs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"mode": s.k.Mode, "port": 0})
}

func (s *APIServer) handlePatchConfigs(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch body.Mode {
	case "rule", "global", "direct":
		s.k.Mode = body.Mode
		s.k.publishSnapshot()
		noContent(w)
	default:
		http.Error(w, "invalid mode", http.StatusBadRequest)
	}
}

func proxyType(p ProxyAdapter) string {
	switch v := p.(type) {
	case *Direct:
		return "Direct"
	case *Reject:
		return "Reject"
	case *ShadowSocks:
		return "Shadowsocks"
	case *VMess:
		return "VMess"
	case *VLESS:
		return "VLESS"
	case *Trojan:
		return "Trojan"
	case *hysteria2Real:
		return "Hysteria2"
	case *tuicReal:
		return "TUIC"
	case *quicOut:
		if v.kind == "tuic" {
			return "TUIC"
		}
		return "Hysteria2"
	case *wgOut:
		return "WireGuard"
	case *ssrOut:
		return "ShadowsocksR"
	case *Selector:
		return "Selector"
	case *URLTest:
		return "URLTest"
	case *Fallback:
		return "Fallback"
	case *LoadBalance:
		return "LoadBalance"
	default:
		return "Proxy"
	}
}

func (s *APIServer) handleProxies(w http.ResponseWriter, r *http.Request) {
	proxies := map[string]any{}
	for name, p := range s.k.Proxies {
		entry := map[string]any{
			"type":    proxyType(p),
			"now":     "",
			"all":     []string{},
			"history": []any{},
			"udp":     false,
		}
		switch g := p.(type) {
		case *Selector:
			entry["now"] = g.Selected()
			entry["all"] = g.Members()
		case *URLTest:
			entry["now"] = g.best()
			entry["all"] = g.Members()
			history := []any{}
			for _, node := range g.Members() {
				if d := g.Delays()[node]; d > 0 {
					history = append(history, map[string]any{
						"time": time.Now().Format(time.RFC3339), "delay": d,
					})
				}
			}
			entry["history"] = history
		case *Fallback:
			entry["all"] = g.Members()
			for _, node := range g.Members() {
				if g.Delays()[node] > 0 {
					entry["now"] = node
					break
				}
			}
		case *LoadBalance:
			entry["all"] = g.Members()
			if len(g.Members()) > 0 {
				entry["now"] = g.Members()[0]
			}
		}
		proxies[name] = entry
	}
	writeJSON(w, map[string]any{"proxies": proxies})
}

func (s *APIServer) handleSelectProxy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, ok := s.k.Proxies[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	sel, ok := p.(Selectable)
	if !ok {
		http.Error(w, "not selectable", http.StatusBadRequest)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !sel.Set(body.Name) {
		http.Error(w, "unknown node", http.StatusBadRequest)
		return
	}
	noContent(w)
}

func (s *APIServer) handleProxyDelay(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, ok := s.k.Proxies[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	testURL := r.URL.Query().Get("url")
	if testURL == "" {
		testURL = s.testURL
	}
	timeout := 5 * time.Second
	if v := r.URL.Query().Get("timeout"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	result := TestDelay(ctx, p, testURL)
	delay := int(result.Delay)
	if result.Error != "" {
		delay = -1
	}
	resp := map[string]any{"delay": delay}
	if result.Error != "" {
		resp["error"] = result.Error
	}
	writeJSON(w, resp)
}

func (s *APIServer) handleGroupDelay(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, ok := s.k.Proxies[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	g, ok := p.(ProxyGroup)
	if !ok {
		http.Error(w, "not a group", http.StatusBadRequest)
		return
	}
	testURL := r.URL.Query().Get("url")
	if testURL == "" {
		testURL = s.testURL
	}
	results := TestGroupDelay(r.Context(), s.k, g, testURL)
	out := map[string]int{}
	for _, res := range results {
		if res.Error != "" {
			out[res.Proxy] = -1
		} else {
			out[res.Proxy] = int(res.Delay)
		}
	}
	writeJSON(w, out)
}

func (s *APIServer) handleRules(w http.ResponseWriter, r *http.Request) {
	rules := []any{}
	for _, rule := range s.k.Rules {
		rules = append(rules, map[string]any{
			"type": rule.Type(), "payload": rule.Payload(), "proxy": rule.Adapter(),
		})
	}
	writeJSON(w, map[string]any{"rules": rules})
}

func (s *APIServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"connections": s.k.Connections.Snapshot()})
}

func (s *APIServer) handleCloseConn(w http.ResponseWriter, r *http.Request) {
	s.k.Connections.Close(r.PathValue("id"))
	noContent(w)
}

func (s *APIServer) handleCloseAll(w http.ResponseWriter, r *http.Request) {
	s.k.Connections.CloseAll()
	noContent(w)
}

func (s *APIServer) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	// 自研内核暂不支持热重载配置；保留接口返回 204 以兼容客户端。
	noContent(w)
}

func (s *APIServer) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	qtype := r.URL.Query().Get("type")
	if qtype == "" {
		qtype = "A"
	}
	resp := map[string]any{
		"Status":   0,
		"Question": []any{map[string]any{"name": name, "type": dnsTypeNum(qtype)}},
		"Answer":   []any{},
	}
	ips, err := net.DefaultResolver.LookupIP(r.Context(), "ip", name)
	answers := []any{}
	if err == nil {
		for _, ip := range ips {
			t := "A"
			if ip.To4() == nil {
				t = "AAAA"
			}
			if qtype != "A" && qtype != "ANY" && qtype != t {
				continue
			}
			answers = append(answers, map[string]any{
				"name": name, "type": dnsTypeNum(t), "TTL": 300, "data": ip.String(),
			})
		}
	}
	resp["Answer"] = answers
	writeJSON(w, resp)
}

func dnsTypeNum(t string) int {
	switch strings.ToUpper(t) {
	case "A":
		return 1
	case "AAAA":
		return 28
	case "CNAME":
		return 5
	case "MX":
		return 15
	default:
		return 1
	}
}

// ---- WebSocket 流 ----

func acceptWS(w http.ResponseWriter, r *http.Request) (*ws.Conn, bool) {
	c, err := ws.Accept(w, r, &ws.AcceptOptions{
		InsecureSkipVerify: true, // 本地控制口，UI wsURL 来自同一 host
	})
	if err != nil {
		return nil, false
	}
	return c, true
}

func (s *APIServer) handleTrafficWS(w http.ResponseWriter, r *http.Request) {
	c, ok := acceptWS(w, r)
	if !ok {
		return
	}
	defer c.Close(ws.StatusNormalClosure, "")
	ctx := c.CloseRead(r.Context())
	writeFrame := func() bool {
		frame := map[string]any{"up": s.upRate.Load(), "down": s.downRate.Load()}
		b, _ := json.Marshal(frame)
		return c.Write(ctx, ws.MessageText, b) == nil
	}
	// 连接建立立即推一帧（UI 与测试都无需等 1 秒 ticker）。
	if !writeFrame() {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !writeFrame() {
				return
			}
		}
	}
}

func (s *APIServer) handleConnectionsWS(w http.ResponseWriter, r *http.Request) {
	c, ok := acceptWS(w, r)
	if !ok {
		return
	}
	defer c.Close(ws.StatusNormalClosure, "")
	ctx := c.CloseRead(r.Context())
	writeFrame := func() bool {
		b, _ := json.Marshal(map[string]any{"connections": s.k.Connections.Snapshot()})
		return c.Write(ctx, ws.MessageText, b) == nil
	}
	if !writeFrame() { // 立即发首帧
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !writeFrame() {
				return
			}
		}
	}
}

// handleConnectionsAny 让 GET /connections 同时服务 REST 与 WebSocket：
// 带 Upgrade 头时升级为 WS，否则返回 JSON。
func (s *APIServer) handleConnectionsAny(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") {
		s.handleConnectionsWS(w, r)
		return
	}
	s.handleConnections(w, r)
}

func (s *APIServer) handleLogsWS(w http.ResponseWriter, r *http.Request) {
	c, ok := acceptWS(w, r)
	if !ok {
		return
	}
	defer c.Close(ws.StatusNormalClosure, "")
	ctx := c.CloseRead(r.Context())
	ch := make(chan LogEntry, 64)
	s.mu.Lock()
	s.logSubs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.logSubs, ch)
		s.mu.Unlock()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-ch:
			b, _ := json.Marshal(entry)
			if err := c.Write(ctx, ws.MessageText, b); err != nil {
				return
			}
		}
	}
}

// Log 广播一条日志给所有 /logs 订阅者。
func (s *APIServer) Log(typ, payload string) {
	entry := LogEntry{Type: typ, Time: time.Now().Format("15:04:05"), Payload: payload}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.logSubs {
		select {
		case ch <- entry:
		default:
		}
	}
}

// rateLoop 每秒计算一次速率（双缓冲，与 自研内核 一致）。
func (s *APIServer) rateLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		up, down := s.k.uploadTotal.Load(), s.k.downloadTotal.Load()
		s.upRate.Store(up - atomic.LoadInt64(&s.lastUpload))
		s.downRate.Store(down - atomic.LoadInt64(&s.lastDownload))
		atomic.StoreInt64(&s.lastUpload, up)
		atomic.StoreInt64(&s.lastDownload, down)
	}
}

// Addr 返回实际监听地址（测试中端口 0 时由系统分配）。
func (s *APIServer) Addr() string { return s.addr }
