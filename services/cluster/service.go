package cluster

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Service provides REST API endpoints for High Availability Clustering and Consensus.
type Service struct {
	manager *ClusterManager
	mux     *http.ServeMux
}

// NewService creates a new Cluster service instance.
func NewService() *Service {
	s := &Service{
		manager: NewClusterManager("airom-ha-cluster-main"),
		mux:     http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the cluster service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Manager returns the underlying ClusterManager.
func (s *Service) Manager() *ClusterManager {
	return s.manager
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/cluster/state", s.handleState)
	s.mux.HandleFunc("/api/v1/cluster/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("/api/v1/cluster/elect", s.handleElect)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-cluster-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	state := s.manager.GetClusterState()

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "table" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(RenderClusterDashboard(state)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(state)
}

func (s *Service) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		NodeID         string   `json:"node_id"`
		ServicesActive []string `json:"services_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.manager.RecordHeartbeat(req.NodeID, req.ServicesActive); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "heartbeat_acknowledged"})
}

func (s *Service) handleElect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	leader, err := s.manager.ElectLeader()
	if err != nil {
		http.Error(w, "Election failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(leader)
}
