package workforce

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Service provides REST API endpoints for workforce impact assessment and duty-of-care tracking.
type Service struct {
	engine  *WorkforceEngine
	mux     *http.ServeMux
	mu      sync.RWMutex
	reports map[string]*WorkforceAssessmentReport
}

// NewService constructs a new Workforce impact service.
func NewService() *Service {
	s := &Service{
		engine:  NewWorkforceEngine(),
		mux:     http.NewServeMux(),
		reports: make(map[string]*WorkforceAssessmentReport),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the workforce service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Engine returns the underlying WorkforceEngine.
func (s *Service) Engine() *WorkforceEngine {
	return s.engine
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/workforce/assess", s.handleAssess)
	s.mux.HandleFunc("/api/v1/workforce/reports", s.handleListReports)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-workforce-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handleAssess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OrganizationID string               `json:"organization_id"`
		SystemName     string               `json:"system_name"`
		Capabilities   []AISystemCapability `json:"capabilities"`
		Roles          []RoleProfile        `json:"roles"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	report, err := s.engine.AssessWorkforceImpact(req.OrganizationID, req.SystemName, req.Capabilities, req.Roles, time.Now().UTC())
	if err != nil {
		http.Error(w, "Assessment failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.reports[report.ReportID] = report
	s.mu.Unlock()

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "table" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(RenderWorkforceDashboard(report)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Service) handleListReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	reportsList := make([]*WorkforceAssessmentReport, 0, len(s.reports))
	for _, rep := range s.reports {
		reportsList = append(reportsList, rep)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(reportsList)
}
