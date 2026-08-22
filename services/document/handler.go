package document

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Server wraps the Agent with HTTP routing.
type Server struct {
	agent *Agent
}

// NewServer instantiates a new HTTP server for the Document Gateway.
func NewServer(agent *Agent) *Server {
	return &Server{agent: agent}
}

// Routes configures all HTTP handlers.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/v1/auth/human-token", s.handleIssueHumanToken)
	mux.HandleFunc("/api/v1/documents/audit-log", s.handleGetAuditLogs)
	mux.HandleFunc("/api/v1/documents", s.handleDocumentsCollection)
	mux.HandleFunc("/api/v1/documents/", s.handleDocumentItem)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "airom-document-agent",
	})
}

// handleIssueHumanToken handles POST /api/v1/auth/human-token.
func (s *Server) handleIssueHumanToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("malformed json: %v", err), http.StatusBadRequest)
		return
	}

	tokenStr, token, err := GenerateHumanToken(s.agent.secret, req, DefaultHumanTokenTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := TokenResponse{
		Token:      tokenStr,
		ExpiresAt:  token.ExpiresAt,
		TTLSeconds: int(DefaultHumanTokenTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleDocumentsCollection handles POST /api/v1/documents.
func (s *Server) handleDocumentsCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreatePackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("malformed json: %v", err), http.StatusBadRequest)
		return
	}

	pkg, err := s.agent.CreatePackage(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(pkg)
}

// handleDocumentItem dispatches sub-actions on /api/v1/documents/{id}/...
func (s *Server) handleDocumentItem(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Expected: api/v1/documents/{id} OR api/v1/documents/{id}/[certify|export|yellow|red]
	if len(parts) < 4 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	docID := parts[3]

	if len(parts) == 4 {
		if r.Method == http.MethodGet {
			pkg, err := s.agent.GetPackage(docID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pkg)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	action := parts[4]
	switch action {
	case "certify":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req CertifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("malformed json: %v", err), http.StatusBadRequest)
			return
		}
		// Also check header fallback
		if req.HumanConfirmationToken == "" {
			req.HumanConfirmationToken = r.Header.Get("X-Human-Confirmation-Token")
		}

		pkg, err := s.agent.CertifyPackage(docID, req)
		if err != nil {
			if strings.Contains(err.Error(), "security check failed") || strings.Contains(err.Error(), "token") {
				http.Error(w, err.Error(), http.StatusForbidden)
			} else {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pkg)

	case "export":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pkg, err := s.agent.GetPackage(docID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		format := r.URL.Query().Get("format")
		if format == "html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(pkg.HTMLPayload))
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write([]byte(pkg.MarkdownPayload))

	case "yellow":
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ItemID string `json:"item_id"`
			Value  string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.agent.UpdateYellowAnswer(docID, body.ItemID, body.Value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)

	case "red":
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ItemID string `json:"item_id"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.agent.AcknowledgeRedGap(docID, body.ItemID, body.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// handleGetAuditLogs handles GET /api/v1/documents/audit-log.
func (s *Server) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logs := s.agent.GetAuditLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}
