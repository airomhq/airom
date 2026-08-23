package provenance

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Service provides REST API endpoints for AI Model Provenance and Lineage tracking.
type Service struct {
	engine *ProvenanceEngine
	mux    *http.ServeMux
}

// NewService constructs a new Provenance service.
func NewService() *Service {
	s := &Service{
		engine: NewProvenanceEngine(nil),
		mux:    http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the provenance service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Engine returns the underlying ProvenanceEngine.
func (s *Service) Engine() *ProvenanceEngine {
	return s.engine
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/provenance/models", s.handleRegisterModel)
	s.mux.HandleFunc("/api/v1/provenance/graph", s.handleGetGraph)
	s.mux.HandleFunc("/api/v1/provenance/verify", s.handleVerify)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-provenance-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handleRegisterModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var node ModelProvenanceNode
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	registered, err := s.engine.RegisterModel(node)
	if err != nil {
		http.Error(w, "Registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(registered)
}

func (s *Service) handleGetGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	modelID := r.URL.Query().Get("model_id")
	if modelID == "" {
		http.Error(w, "Missing query param 'model_id'", http.StatusBadRequest)
		return
	}

	graph, err := s.engine.BuildLineageGraph(modelID)
	if err != nil {
		http.Error(w, "Failed to build graph: "+err.Error(), http.StatusNotFound)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "tree" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(RenderProvenanceTree(graph)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(graph)
}

func (s *Service) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ModelID          string `json:"model_id"`
		ActualWeightsSHA string `json:"actual_weights_sha"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	result, err := s.engine.VerifyModelProvenance(req.ModelID, req.ActualWeightsSHA)
	if err != nil {
		http.Error(w, "Verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
