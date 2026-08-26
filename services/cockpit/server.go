package cockpit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Server serves the interactive enterprise cockpit dashboard and REST API.
type Server struct {
	mu     sync.RWMutex
	config CockpitConfig
	state  CockpitState
	events []CockpitEvent
}

// NewServer constructs a new web cockpit server.
func NewServer(cfg CockpitConfig) *Server {
	if cfg.Port == 0 {
		cfg.Port = 8088
	}
	if cfg.Organization == "" {
		cfg.Organization = "Enterprise AI Systems"
	}

	return &Server{
		config: cfg,
		state: CockpitState{
			Organization:     cfg.Organization,
			TotalComponents:  7,
			TotalGaps:        0,
			TotalMetControls: 12,
			ActiveModels:     []string{"gpt-4o-mini", "claude-3-5-sonnet", "nomic-embed-text"},
			SyncStatus:       "SYNCHRONIZED",
			UpdatedAt:        time.Now().UTC(),
		},
		events: make([]CockpitEvent, 0),
	}
}

// Routes initializes the HTTP multiplexer.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/v1/state", s.handleState)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AIROM Enterprise Governance Cockpit — %s</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    h1 { color: #38bdf8; font-size: 1.8rem; margin-bottom: 0.5rem; }
    .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; background: #22c55e; color: #000; font-size: 0.85rem; }
  </style>
</head>
<body>
  <h1>AIROM Enterprise Governance Cockpit</h1>
  <div class="card">
    <h2>Organization: %s</h2>
    <span class="badge">STATUS: %s</span>
  </div>
</body>
</html>`, s.state.Organization, s.state.Organization, s.state.SyncStatus)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.state)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.events)
}

// PushEvent broadcasts a real-time event to the cockpit.
func (s *Server) PushEvent(evt CockpitEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	evt.Timestamp = time.Now().UTC()
	s.events = append(s.events, evt)
}
