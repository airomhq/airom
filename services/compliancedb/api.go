package compliancedb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IngestionRequest is the payload sent by CI / scanner to ingest a scan snapshot.
type IngestionRequest struct {
	RepoID               string              `json:"repo_id"`
	CommitSHA            string              `json:"commit_sha"`
	Branch               string              `json:"branch"`
	ScanTimestamp        time.Time           `json:"scan_timestamp"`
	AIBOMSHA256          string              `json:"aibom_sha256"`
	ComponentsCount      int                 `json:"components_count"`
	VulnerabilitiesCount int                 `json:"vulnerabilities_count"`
	ControlsMet          int                 `json:"controls_met"`
	ControlsGap          int                 `json:"controls_gap"`
	ControlsManual       int                 `json:"controls_manual"`
	Evaluations          []ControlEvaluation `json:"evaluations,omitempty"`
	RawAIBOM             json.RawMessage     `json:"raw_aibom,omitempty"`
}

// IngestionResponse is returned upon successful snapshot ingestion.
type IngestionResponse struct {
	SnapshotID        string               `json:"snapshot_id"`
	SelfHash          string               `json:"self_hash"`
	PrevHash          string               `json:"prev_hash"`
	NewIncidentsCount int                  `json:"new_incidents_count"`
	ResolvedIncidents []ComplianceIncident `json:"resolved_incidents,omitempty"`
	ChainStatus       string               `json:"chain_status"` // VALID, BROKEN
}

// OrgComplianceRegulationStats aggregates control verdicts for one regulation.
type OrgComplianceRegulationStats struct {
	RegulationID string `json:"regulation_id"`
	MetCount     int    `json:"met_count"`
	GapCount     int    `json:"gap_count"`
	ManualCount  int    `json:"manual_count"`
	TotalRepos   int    `json:"total_repos"`
}

// OrgComplianceResponse is returned by GET /api/v1/orgs/{org}/compliance.
type OrgComplianceResponse struct {
	OrgID       string                         `json:"org_id"`
	TotalRepos  int                            `json:"total_repos"`
	TotalGaps   int                            `json:"total_gaps"`
	TotalMet    int                            `json:"total_met"`
	TotalManual int                            `json:"total_manual"`
	Regulations []OrgComplianceRegulationStats `json:"regulations"`
	GeneratedAt time.Time                      `json:"generated_at"`
}

// RepoHistoryResponse is returned by GET /api/v1/repos/{repo}/history.
type RepoHistoryResponse struct {
	RepoID      string                  `json:"repo_id"`
	Snapshots   []ScanSnapshot          `json:"snapshots"`
	ChainReport ChainVerificationReport `json:"chain_report"`
	TotalCount  int                     `json:"total_count"`
	GeneratedAt time.Time               `json:"generated_at"`
}

// RepoIncidentsResponse is returned by GET /api/v1/repos/{repo}/incidents.
type RepoIncidentsResponse struct {
	RepoID    string               `json:"repo_id"`
	OpenCount int                  `json:"open_count"`
	Resolved  int                  `json:"resolved_count"`
	Incidents []ComplianceIncident `json:"incidents"`
}

// Service provides the ComplianceDB HTTP REST API server with an in-memory thread-safe state store.
type Service struct {
	mu          sync.RWMutex
	orgs        map[string]*Organization
	repos       map[string]*Repository
	repoByOrg   map[string][]string             // orgID -> []repoID
	snapshots   map[string][]ScanSnapshot       // repoID -> []ScanSnapshot
	incidents   map[string][]ComplianceIncident // repoID -> []ComplianceIncident
	evaluations map[string][]ControlEvaluation  // snapshotID -> []ControlEvaluation
}

// NewService instantiates a new ComplianceDB API service.
func NewService() *Service {
	return &Service{
		orgs:        make(map[string]*Organization),
		repos:       make(map[string]*Repository),
		repoByOrg:   make(map[string][]string),
		snapshots:   make(map[string][]ScanSnapshot),
		incidents:   make(map[string][]ComplianceIncident),
		evaluations: make(map[string][]ControlEvaluation),
	}
}

// RegisterOrg seeds or creates an organization tenant.
func (s *Service) RegisterOrg(org Organization) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[org.ID] = &org
	if org.Slug != "" && org.Slug != org.ID {
		s.orgs[org.Slug] = &org
	}
}

// RegisterRepo links a repository to an organization.
func (s *Service) RegisterRepo(repo Repository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[repo.ID] = &repo
	s.repoByOrg[repo.OrgID] = append(s.repoByOrg[repo.OrgID], repo.ID)
}

// Routes returns a configured http.Handler with all REST endpoints.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.HealthzHandler)
	mux.HandleFunc("/api/v1/orgs/", s.handleOrgsRoute)
	mux.HandleFunc("/api/v1/repos/", s.handleReposRoute)
	return mux
}

// HealthzHandler handles GET /healthz.
func (s *Service) HealthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "airom-compliancedb",
	})
}

// handleOrgsRoute dispatches /api/v1/orgs/{org}/compliance.
func (s *Service) handleOrgsRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Expected format: api/v1/orgs/{org}/compliance
	if len(parts) != 5 || parts[4] != "compliance" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := parts[3]
	s.GetOrgComplianceHandler(w, r, orgID)
}

// handleReposRoute dispatches /api/v1/repos/{repo}/[history|snapshots|incidents].
func (s *Service) handleReposRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Expected format: api/v1/repos/{repo}/[history|snapshots|incidents]
	if len(parts) != 5 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	repoID := parts[3]
	action := parts[4]

	switch action {
	case "history":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.GetRepoHistoryHandler(w, r, repoID)
	case "snapshots":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.IngestSnapshotHandler(w, r, repoID)
	case "incidents":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.GetRepoIncidentsHandler(w, r, repoID)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// GetOrgComplianceHandler aggregates compliance across all repositories in an organization.
func (s *Service) GetOrgComplianceHandler(w http.ResponseWriter, r *http.Request, orgID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	repoIDs := s.repoByOrg[orgID]
	// Also check if org was registered by slug
	if len(repoIDs) == 0 && s.orgs[orgID] != nil {
		actualOrg := s.orgs[orgID]
		repoIDs = s.repoByOrg[actualOrg.ID]
	}

	resp := OrgComplianceResponse{
		OrgID:       orgID,
		TotalRepos:  len(repoIDs),
		GeneratedAt: time.Now().UTC(),
		Regulations: make([]OrgComplianceRegulationStats, 0),
	}

	regMap := make(map[string]*OrgComplianceRegulationStats)

	for _, repoID := range repoIDs {
		snaps := s.snapshots[repoID]
		if len(snaps) == 0 {
			continue
		}
		latestSnap := snaps[len(snaps)-1]
		resp.TotalMet += latestSnap.ControlsMet
		resp.TotalGaps += latestSnap.ControlsGap
		resp.TotalManual += latestSnap.ControlsManual

		evals := s.evaluations[latestSnap.ID]
		for _, ev := range evals {
			regKey := ev.StatuteRef
			if regKey == "" {
				regKey = "General"
			}
			st, ok := regMap[regKey]
			if !ok {
				st = &OrgComplianceRegulationStats{
					RegulationID: regKey,
				}
				regMap[regKey] = st
			}
			switch ev.Verdict {
			case VerdictMet:
				st.MetCount++
			case VerdictGap:
				st.GapCount++
			case VerdictManual:
				st.ManualCount++
			}
		}
	}

	for _, st := range regMap {
		st.TotalRepos = len(repoIDs)
		resp.Regulations = append(resp.Regulations, *st)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetRepoHistoryHandler returns the time-series snapshot history and chain report for a repo.
func (s *Service) GetRepoHistoryHandler(w http.ResponseWriter, r *http.Request, repoID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snaps := s.snapshots[repoID]
	if snaps == nil {
		snaps = []ScanSnapshot{}
	}

	chainReport := ValidateChain(snaps)

	resp := RepoHistoryResponse{
		RepoID:      repoID,
		Snapshots:   snaps,
		ChainReport: chainReport,
		TotalCount:  len(snaps),
		GeneratedAt: time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// IngestSnapshotHandler ingests a scan snapshot, appends to the cryptographic ledger, and processes incidents.
func (s *Service) IngestSnapshotHandler(w http.ResponseWriter, r *http.Request, repoID string) {
	var req IngestionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("malformed json request: %v", err), http.StatusBadRequest)
		return
	}

	if req.RepoID != "" && req.RepoID != repoID {
		http.Error(w, fmt.Sprintf("mismatched repo_id in payload (%q) and URL path (%q)", req.RepoID, repoID), http.StatusBadRequest)
		return
	}
	if req.RepoID == "" {
		req.RepoID = repoID
	}
	if req.CommitSHA == "" {
		http.Error(w, "commit_sha is required", http.StatusBadRequest)
		return
	}
	if req.ControlsMet < 0 || req.ControlsGap < 0 || req.ControlsManual < 0 || req.ComponentsCount < 0 || req.VulnerabilitiesCount < 0 {
		http.Error(w, "negative compliance metrics or component counts are invalid", http.StatusBadRequest)
		return
	}
	if req.ScanTimestamp.IsZero() {
		req.ScanTimestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	chain := s.snapshots[repoID]
	prevHash := ""
	if len(chain) > 0 {
		prevHash = chain[len(chain)-1].SelfHash
	}

	snapID := fmt.Sprintf("snap-%s-%d", repoID, req.ScanTimestamp.UnixNano())
	snap := NewSnapshot(
		snapID,
		repoID,
		req.CommitSHA,
		req.Branch,
		req.ScanTimestamp,
		req.AIBOMSHA256,
		req.ComponentsCount,
		req.VulnerabilitiesCount,
		req.ControlsMet,
		req.ControlsGap,
		req.ControlsManual,
		prevHash,
		req.RawAIBOM,
	)

	// Save snapshot to ledger
	s.snapshots[repoID] = append(s.snapshots[repoID], snap)

	// Store evaluations
	for i := range req.Evaluations {
		req.Evaluations[i].SnapshotID = snapID
		if req.Evaluations[i].ID == "" {
			req.Evaluations[i].ID = fmt.Sprintf("eval-%s-%d", snapID, i)
		}
	}
	s.evaluations[snapID] = req.Evaluations

	// Process compliance incidents
	existingIncidents := s.incidents[repoID]
	newIncs, resolvedIncs, remainingOpen := ProcessSnapshotIncidents(existingIncidents, snap, req.Evaluations)

	// Update incidents list
	var updatedIncidents []ComplianceIncident
	for _, inc := range existingIncidents {
		// Keep already resolved incidents
		if inc.Status == IncidentStatusResolved {
			updatedIncidents = append(updatedIncidents, inc)
		}
	}
	updatedIncidents = append(updatedIncidents, remainingOpen...)
	updatedIncidents = append(updatedIncidents, newIncs...)
	updatedIncidents = append(updatedIncidents, resolvedIncs...)
	s.incidents[repoID] = updatedIncidents

	// Verify updated chain status
	chainReport := ValidateChain(s.snapshots[repoID])
	chainStatus := "VALID"
	if !chainReport.Valid {
		chainStatus = "BROKEN"
	}

	resp := IngestionResponse{
		SnapshotID:        snapID,
		SelfHash:          snap.SelfHash,
		PrevHash:          prevHash,
		NewIncidentsCount: len(newIncs),
		ResolvedIncidents: resolvedIncs,
		ChainStatus:       chainStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetRepoIncidentsHandler returns all open and resolved incidents for a repository.
func (s *Service) GetRepoIncidentsHandler(w http.ResponseWriter, r *http.Request, repoID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	incs := s.incidents[repoID]
	if incs == nil {
		incs = []ComplianceIncident{}
	}

	openCount := 0
	resolvedCount := 0
	for _, inc := range incs {
		if inc.Status == IncidentStatusOpen {
			openCount++
		} else if inc.Status == IncidentStatusResolved {
			resolvedCount++
		}
	}

	resp := RepoIncidentsResponse{
		RepoID:    repoID,
		OpenCount: openCount,
		Resolved:  resolvedCount,
		Incidents: incs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
