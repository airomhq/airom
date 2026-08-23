package redteam

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Service provides REST API endpoints for Automated Red Team Security Penetration testing.
type Service struct {
	engine      *RedTeamEngine
	mux         *http.ServeMux
	mu          sync.RWMutex
	assessments map[string]*RedTeamAssessment // Key: AssessmentID
}

// NewService creates a new Red Team service instance.
func NewService() *Service {
	s := &Service{
		engine:      NewRedTeamEngine(),
		mux:         http.NewServeMux(),
		assessments: make(map[string]*RedTeamAssessment),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the red team service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Engine returns the underlying RedTeamEngine.
func (s *Service) Engine() *RedTeamEngine {
	return s.engine
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/redteam/probe", s.handleProbe)
	s.mux.HandleFunc("/api/v1/redteam/assessments", s.handleListAssessments)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-redteam-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		TargetEndpoint     string            `json:"target_endpoint"`
		TargetModel        string            `json:"target_model"`
		SimulatedResponses map[string]string `json:"simulated_responses"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	assessment, err := s.engine.ExecuteAssessment(r.Context(), req.TargetEndpoint, req.TargetModel, req.SimulatedResponses)
	if err != nil {
		http.Error(w, "Assessment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.assessments[assessment.AssessmentID] = assessment
	s.mu.Unlock()

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "table" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(RenderRedTeamDashboard(assessment)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(assessment)
}

func (s *Service) handleListAssessments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	list := make([]*RedTeamAssessment, 0, len(s.assessments))
	for _, a := range s.assessments {
		list = append(list, a)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)
}
