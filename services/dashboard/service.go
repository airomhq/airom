package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Service provides REST API endpoints for Enterprise Compliance Dashboard v2.
type Service struct {
	engine       *DashboardEngine
	mux          *http.ServeMux
	mu           sync.RWMutex
	latestMatrix *MultiOrgPostureMatrix
}

// NewService creates a new Dashboard service instance.
func NewService() *Service {
	s := &Service{
		engine: NewDashboardEngine(),
		mux:    http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the dashboard service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Engine returns the underlying DashboardEngine.
func (s *Service) Engine() *DashboardEngine {
	return s.engine
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/dashboard/posture", s.handlePosture)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-dashboard-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handlePosture(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Organizations []OrganizationRollup `json:"organizations"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		matrix, err := s.engine.CalculateExecutivePosture(req.Organizations)
		if err != nil {
			http.Error(w, "Calculation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.mu.Lock()
		s.latestMatrix = matrix
		s.mu.Unlock()

		format := strings.ToLower(r.URL.Query().Get("format"))
		if format == "text" || format == "table" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(RenderExecutiveDashboard(matrix)))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(matrix)

	case http.MethodGet:
		s.mu.RLock()
		matrix := s.latestMatrix
		s.mu.RUnlock()

		if matrix == nil {
			// Generate sample baseline if no POST occurred yet
			matrix, _ = s.engine.CalculateExecutivePosture(nil)
		}

		format := strings.ToLower(r.URL.Query().Get("format"))
		if format == "text" || format == "table" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(RenderExecutiveDashboard(matrix)))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(matrix)

	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}
