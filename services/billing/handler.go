package billing

import (
	"encoding/json"
	"io"
	"net/http"
)

// Routes attaches billing HTTP endpoints to an ServeMux.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()

	// POST /api/v1/billing/webhook/stripe
	mux.HandleFunc("/api/v1/billing/webhook/stripe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}

		sigHeader := r.Header.Get("Stripe-Signature")
		if err := s.HandleStripeWebhook(payload, sigHeader); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "processed"})
	})

	// GET /api/v1/billing/subscription?org_id=xxx
	mux.HandleFunc("/api/v1/billing/subscription", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			http.Error(w, "missing org_id parameter", http.StatusBadRequest)
			return
		}

		acc, ok := s.GetAccount(orgID)
		if !ok {
			// Return default community profile
			acc = &CustomerAccount{
				OrgID:  orgID,
				Tier:   TierCommunity,
				Status: StatusActive,
			}
		}

		quotas := DefaultQuotas(acc.Tier)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"account": acc,
			"quotas":  quotas,
		})
	})

	// GET /api/v1/billing/usage?org_id=xxx
	mux.HandleFunc("/api/v1/billing/usage", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		orgID := r.URL.Query().Get("org_id")
		if orgID == "" {
			http.Error(w, "missing org_id parameter", http.StatusBadRequest)
			return
		}

		usage := s.GetUsage(orgID)
		acc, ok := s.GetAccount(orgID)
		tier := TierCommunity
		if ok {
			tier = acc.Tier
		}
		quotas := DefaultQuotas(tier)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"usage":  usage,
			"quotas": quotas,
			"tier":   tier,
		})
	})

	return mux
}
