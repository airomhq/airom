package filing

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Service provides HTTP REST endpoints and internal coordination for filings and renewal schedules.
type Service struct {
	builder *PackageBuilder
	engine  *RenewalEngine
	agent   *FilingAgent
	mux     *http.ServeMux
}

// NewService constructs a new filing and renewal coordinator service.
func NewService() *Service {
	s := &Service{
		builder: NewPackageBuilder(),
		engine:  NewRenewalEngine(),
		agent:   NewFilingAgent(nil),
		mux:     http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the filing service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Builder returns the underlying PackageBuilder.
func (s *Service) Builder() *PackageBuilder {
	return s.builder
}

// Engine returns the underlying RenewalEngine.
func (s *Service) Engine() *RenewalEngine {
	return s.engine
}

// Agent returns the underlying FilingAgent.
func (s *Service) Agent() *FilingAgent {
	return s.agent
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/filings/generate", s.handleGenerate)
	s.mux.HandleFunc("/api/v1/filings/submit", s.handleSubmit)
	s.mux.HandleFunc("/api/v1/filings/receipts", s.handleReceipts)
	s.mux.HandleFunc("/api/v1/calendar", s.handleCalendar)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-filing-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var opts BuildPackageOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	manifest, err := s.builder.BuildPackage(opts)
	if err != nil {
		http.Error(w, "Failed to build filing package: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(manifest)
}

func (s *Service) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Manifest  FilingManifest `json:"manifest"`
		PortalURL string         `json:"portal_url,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	receipt, err := s.agent.SubmitPackage(r.Context(), &req.Manifest, req.PortalURL)
	if err != nil {
		http.Error(w, "Filing submission failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipt)
}

func (s *Service) handleReceipts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := r.URL.Query().Get("org")
	if orgID == "" {
		http.Error(w, "Missing query parameter 'org'", http.StatusBadRequest)
		return
	}

	receipts := s.agent.GetReceipts(orgID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(receipts)
}

func (s *Service) handleCalendar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := r.URL.Query().Get("org")
	if orgID == "" {
		orgID = "default-org"
	}

	history := make(FilingHistoryMap)
	mods := make(SubstantialModMap)

	// Ingest past receipts to determine last filing dates
	for _, rcpt := range s.agent.GetReceipts(orgID) {
		if cur, ok := history[rcpt.Jurisdiction]; !ok || rcpt.SubmittedAt.After(cur) {
			history[rcpt.Jurisdiction] = rcpt.SubmittedAt
		}
	}

	cal := s.engine.ComputeCalendar(orgID, history, mods, time.Now().UTC())

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "table" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(s.engine.RenderCalendarTable(cal)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(cal)
}
