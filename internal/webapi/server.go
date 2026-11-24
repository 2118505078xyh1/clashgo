// Package webapi exposes a small, controlled REST API and an SSE event stream
// so external tools and scripts can observe clashgo state and react to events.
//
// It is intentionally decoupled from the ui package: the caller feeds the
// server a Snapshot via SetSnapshot and forwards events via Publish.
package webapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is reported by GET /api/version.
const Version = "clashgo/1.0"

const (
	// keepAliveInterval is the SSE heartbeat period used to keep proxies from
	// closing an otherwise idle streaming connection.
	keepAliveInterval = 15 * time.Second
	// maxSubscribers caps the number of concurrent /api/events clients.
	maxSubscribers = 50
	// subscriberBuffer is the per-subscriber event buffer. A subscriber that
	// does not drain it in time loses the oldest/newest overflow events instead
	// of stalling every other subscriber.
	subscriberBuffer = 64
)

// Snapshot is an immutable view of the application state served to clients.
type Snapshot struct {
	Version     string         `json:"version"`
	Mode        string         `json:"mode"`
	Up          int64          `json:"up"`
	Down        int64          `json:"down"`
	Connections int            `json:"connections"`
	Proxies     map[string]any `json:"proxies"`
	Rules       []any          `json:"rules"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Event is a single item broadcast on the SSE stream.
type Event struct {
	Type string    `json:"type"`
	Data any       `json:"data"`
	Time time.Time `json:"time"`
}

// CommandHandler executes a command received on POST /api/command.
// action is one of "set-mode", "toggle-system-proxy" or "reload-config".
type CommandHandler func(action, value string) error

type subscriber struct {
	id int
	ch chan Event
}

// Server is the Web API server.
type Server struct {
	Addr   string
	Secret string

	snapMu sync.RWMutex
	snap   Snapshot

	cmdMu      sync.RWMutex
	cmdHandler CommandHandler

	subsMu    sync.Mutex
	subs      map[int]*subscriber
	nextSubID int

	srvMu sync.Mutex
	srv   *http.Server
	ln    net.Listener
}

// New creates a server bound to addr. An empty secret disables authentication
// (useful for local testing); callers should normally supply a secret.
func New(addr, secret string) *Server {
	return &Server{
		Addr:   addr,
		Secret: secret,
		subs:   make(map[int]*subscriber),
	}
}

// SetSnapshot atomically replaces the state snapshot. Defensive copies of the
// map/slice are taken so later mutations by the caller cannot race with JSON
// encoding of an in-flight response.
func (s *Server) SetSnapshot(snap Snapshot) {
	if snap.Proxies != nil {
		m := make(map[string]any, len(snap.Proxies))
		for k, v := range snap.Proxies {
			m[k] = v
		}
		snap.Proxies = m
	}
	if snap.Rules != nil {
		snap.Rules = append([]any(nil), snap.Rules...)
	}
	s.snapMu.Lock()
	s.snap = snap
	s.snapMu.Unlock()
}

// Snapshot returns the current state snapshot.
func (s *Server) Snapshot() Snapshot {
	s.snapMu.RLock()
	defer s.snapMu.RUnlock()
	return s.snap
}

// SetCommandHandler installs the callback used to execute API commands.
func (s *Server) SetCommandHandler(h CommandHandler) {
	s.cmdMu.Lock()
	s.cmdHandler = h
	s.cmdMu.Unlock()
}

// Publish broadcasts an event to every SSE subscriber. Events are dropped for
// subscribers whose buffer is full, so a slow client never blocks the others.
func (s *Server) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	for _, sub := range s.subs {
		select {
		case sub.ch <- e:
		default:
			// slow subscriber: drop the event
		}
	}
}

// subscribe registers a new SSE subscriber. It returns nil when the subscriber
// limit has been reached.
func (s *Server) subscribe() *subscriber {
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if len(s.subs) >= maxSubscribers {
		return nil
	}
	sub := &subscriber{id: s.nextSubID, ch: make(chan Event, subscriberBuffer)}
	s.nextSubID++
	s.subs[sub.id] = sub
	return sub
}

// unsubscribe removes a subscriber and closes its channel. Publish and
// unsubscribe share subsMu, so a send can never race with a close.
func (s *Server) unsubscribe(sub *subscriber) {
	if sub == nil {
		return
	}
	s.subsMu.Lock()
	defer s.subsMu.Unlock()
	if _, ok := s.subs[sub.id]; !ok {
		return
	}
	delete(s.subs, sub.id)
	close(sub.ch)
}

// Start binds Addr and serves the API until Close is called. It returns nil
// after a graceful shutdown.
func (s *Server) Start() error {
	s.srvMu.Lock()
	if s.srv != nil {
		s.srvMu.Unlock()
		return errors.New("webapi: server already started")
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		s.srvMu.Unlock()
		return err
	}
	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.ln, s.srv = ln, srv
	s.srvMu.Unlock()

	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close shuts the server down. Active SSE handlers observe a cancelled request
// context, exit and unregister themselves, releasing their channels.
func (s *Server) Close() {
	s.srvMu.Lock()
	srv := s.srv
	s.srvMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

// handler builds the HTTP handler. Kept unexported so tests (same package) can
// drive the routes with httptest without opening a real socket.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", s.serveVersion)
	mux.HandleFunc("/api/status", s.serveStatus)
	mux.HandleFunc("/api/events", s.serveEvents)
	mux.HandleFunc("/api/command", s.serveCommand)
	return s.withMiddleware(mux)
}

// withMiddleware handles CORS and bearer-token authentication for all /api/*
// routes. Preflight requests are answered before auth (browsers omit the token
// on OPTIONS) and only same-origin CORS is permitted.
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORS(w, r)
		if r.Method == http.MethodOptions && strings.HasPrefix(r.URL.Path, "/api/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && s.Secret != "" {
			const prefix = "Bearer "
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, prefix) || strings.TrimPrefix(auth, prefix) != s.Secret {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// setCORS reflects the Origin only when it matches the request host. Same-origin
// requests need no CORS at all, and no wildcard is ever emitted.
func setCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host != r.Host {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) serveVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"version": Version})
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.Snapshot())
}

func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	since := parseSince(r.URL.Query().Get("since"))
	sub := s.subscribe()
	if sub == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "too many subscribers"})
		return
	}
	defer s.unsubscribe(sub)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	heartbeat := time.NewTicker(keepAliveInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ":keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case e := <-sub.ch:
			if !since.IsZero() && e.Time.Before(since) {
				continue
			}
			if err := writeSSE(w, e); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// parseSince accepts either a Unix timestamp (seconds or milliseconds) or an
// RFC3339 string. An empty or unparseable value means "no lower bound".
func parseSince(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if n > 1e12 { // milliseconds
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	return time.Time{}
}

func sseEventType(t string) string {
	t = strings.ReplaceAll(t, "\n", " ")
	t = strings.ReplaceAll(t, "\r", " ")
	if t == "" {
		return "message"
	}
	return t
}

func writeSSE(w io.Writer, e Event) error {
	data, err := json.Marshal(e.Data)
	if err != nil {
		data = []byte("null")
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", sseEventType(e.Type), data)
	return err
}

func (s *Server) serveCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	var req struct {
		Action string `json:"action"`
		Value  string `json:"value"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}
	switch req.Action {
	case "set-mode", "toggle-system-proxy", "reload-config":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown action", "action": req.Action})
		return
	}

	s.cmdMu.RLock()
	h := s.cmdHandler
	s.cmdMu.RUnlock()
	if h == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "command handler not configured"})
		return
	}
	if err := h(req.Action, req.Value); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
