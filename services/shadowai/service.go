package shadowai

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RenderInventoryDashboard formats an ASCII terminal dashboard of discovered Shadow AI assets.
func RenderInventoryDashboard(inv *ShadowAIInventory) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "  AIROM SHADOW AI & SAAS CONNECTOR ASSET INVENTORY\n")
	fmt.Fprintf(&sb, "  Organization: %s | Scanned: %s\n", inv.OrganizationID, inv.ScannedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "  Discovered: %d | Critical: %d | High: %d | Medium: %d | Approved: %d\n",
		inv.TotalDiscovered, inv.CriticalCount, inv.HighCount, inv.MediumCount, inv.ApprovedCount)
	fmt.Fprintf(&sb, "====================================================================================================\n")

	if len(inv.Findings) == 0 {
		fmt.Fprintf(&sb, "  ✅ No unauthorized or shadow AI tools detected across scanned workspace.\n")
		fmt.Fprintf(&sb, "====================================================================================================\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "%-14s | %-16s | %-10s | %-24s | %-24s\n", "PLATFORM", "CATEGORY", "SEVERITY", "LOCATION", "SNIPPET")
	fmt.Fprintf(&sb, "---------------+------------------+------------+--------------------------+-------------------------\n")

	for _, f := range inv.Findings {
		loc := f.Location
		if len(loc) > 24 {
			loc = "..." + loc[len(loc)-21:]
		}
		snip := f.TokenSnippet
		if len(snip) > 24 {
			snip = snip[:21] + "..."
		}
		fmt.Fprintf(&sb, "%-14s | %-16s | %-10s | %-24s | %-24s\n",
			f.Platform, f.Category, f.Severity, loc, snip)
	}

	fmt.Fprintf(&sb, "\n--- ACTIONABLE COMPLIANCE POLICY REMEDIATIONS ---\n")
	for i, f := range inv.Findings {
		if f.Severity == RiskCritical || f.Severity == RiskHigh {
			fmt.Fprintf(&sb, "  [%d] %s at %s (%s):\n      Policy: %s\n      Action: %s\n",
				i+1, f.ToolName, f.Location, f.Severity, f.PolicyViolation, f.RemediationAction)
		}
	}

	fmt.Fprintf(&sb, "====================================================================================================\n")
	return sb.String()
}

// Service provides REST API endpoints for Shadow AI scanning and inventory management.
type Service struct {
	detector    *ShadowAIDetector
	mux         *http.ServeMux
	mu          sync.RWMutex
	inventories map[string]*ShadowAIInventory // Key: InventoryID
}

// NewService creates a new Shadow AI service.
func NewService() *Service {
	s := &Service{
		detector:    NewShadowAIDetector(),
		mux:         http.NewServeMux(),
		inventories: make(map[string]*ShadowAIInventory),
	}
	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the shadowai service.
func (s *Service) Routes() http.Handler {
	return s.mux
}

// Detector returns the underlying ShadowAIDetector.
func (s *Service) Detector() *ShadowAIDetector {
	return s.detector
}

func (s *Service) setupRoutes() {
	s.mux.HandleFunc("/api/v1/shadowai/scan", s.handleScan)
	s.mux.HandleFunc("/api/v1/shadowai/inventories", s.handleListInventories)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-shadowai-service",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Service) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OrganizationID    string         `json:"organization_id"`
		ApprovedPlatforms []SaaSPlatform `json:"approved_platforms"`
		Files             []FileEntry    `json:"files"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	opts := DetectorOptions{
		OrganizationID:    req.OrganizationID,
		ApprovedPlatforms: req.ApprovedPlatforms,
	}

	inventory, err := s.detector.ScanFiles(req.Files, opts)
	if err != nil {
		http.Error(w, "Scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.inventories[inventory.InventoryID] = inventory
	s.mu.Unlock()

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "text" || format == "table" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(RenderInventoryDashboard(inventory)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(inventory)
}

func (s *Service) handleListInventories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	list := make([]*ShadowAIInventory, 0, len(s.inventories))
	for _, inv := range s.inventories {
		list = append(list, inv)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)
}
