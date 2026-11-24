// Package pac serves a PAC (proxy auto-config) file over a local HTTP
// port so the OS can use "auto proxy" mode.
package pac

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// DefaultPAC is the standard a reference GUI PAC content.
const DefaultPAC = `function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host === "127.0.0.1" || host === "localhost" ||
      shExpMatch(host, "*.local") || shExpMatch(host, "*.arpa")) {
    return "DIRECT";
  }
  return "PROXY 127.0.0.1:7897; SOCKS5 127.0.0.1:7897; DIRECT";
}
`

// Server is a local PAC file HTTP server.
type Server struct {
	mu      sync.Mutex
	server  *http.Server
	port    int
	content string
	version int
}

// New creates a PAC server (not yet started).
func New(content string) *Server {
	if content == "" {
		content = DefaultPAC
	}
	return &Server{content: content}
}

// Start binds an ephemeral local port and serves the PAC file.
func (s *Server) Start() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return s.port, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	s.port = ln.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		s.mu.Lock()
		body := s.content
		version := s.version
		s.mu.Unlock()
		// Replace the %version% placeholder if present, otherwise ignore.
		body = strings.ReplaceAll(body, "%version%", fmt.Sprint(version))
		_, _ = w.Write([]byte(body))
	})
	s.server = &http.Server{Handler: mux}
	go func() { _ = s.server.Serve(ln) }()
	return s.port, nil
}

// URL returns the PAC URL for the running server.
func (s *Server) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.port == 0 {
		return ""
	}
	return fmt.Sprintf("http://127.0.0.1:%d/proxy.pac?v=%d", s.port, s.version)
}

// SetContent updates the served PAC script.
func (s *Server) SetContent(content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(content) != "" {
		s.content = content
		s.version++
	}
}

// Stop shuts down the PAC server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		_ = s.server.Close()
		s.server = nil
		s.port = 0
	}
}
