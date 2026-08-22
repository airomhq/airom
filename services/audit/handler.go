package audit

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Routes attaches SOC 2 Audit and SIEM management endpoints to an http.ServeMux.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()

	// GET /api/v1/audit/events?org_id=xxx
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			http.Error(w, "missing org_id parameter", http.StatusBadRequest)
			return
		}
		events := s.GetEvents(orgID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"events": events,
			"total":  len(events),
		})
	})

	// POST /api/v1/audit/events (Ingest external/internal audit event)
	mux.HandleFunc("/api/v1/audit/events/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var evt AuditEvent
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if evt.OrgID == "" || evt.Action == "" || evt.Resource == "" {
			http.Error(w, "missing required fields (org_id, action, resource)", http.StatusBadRequest)
			return
		}

		recorded, err := s.RecordEvent(r.Context(), evt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(recorded)
	})

	// POST /api/v1/audit/siem/config
	mux.HandleFunc("/api/v1/audit/siem/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var cfg SIEMConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.ConfigureSIEM(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "configured",
			"config": cfg,
		})
	})

	// GET /api/v1/audit/siem/config?org_id=xxx
	mux.HandleFunc("/api/v1/audit/siem/config/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			http.Error(w, "missing org_id parameter", http.StatusBadRequest)
			return
		}
		cfg, ok := s.GetSIEMConfig(orgID)
		if !ok {
			http.Error(w, "siem config not found", http.StatusNotFound)
			return
		}
		// Redact secrets in response
		cfg.APIKey = maskSecret(cfg.APIKey)
		cfg.SecretKey = maskSecret(cfg.SecretKey)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg) // #nosec G117 -- secrets are explicitly masked above before encoding
	})

	return mux
}

func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
