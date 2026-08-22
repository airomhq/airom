package anomaly

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

type EvaluateRequest struct {
	RepoID       string          `json:"repo_id"`
	BaseCommit   string          `json:"base_commit"`
	HeadCommit   string          `json:"head_commit"`
	BaseAIBOM    airom.Inventory `json:"base_aibom"`
	HeadAIBOM    airom.Inventory `json:"head_aibom"`
	ManifestYAML string          `json:"manifest_yaml"`
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) EvaluateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Malformed JSON", http.StatusBadRequest)
		return
	}

	anomalies := []Anomaly{}
	if len(req.HeadAIBOM.Components) > len(req.BaseAIBOM.Components) {
		anomalies = append(anomalies, Anomaly{
			Type:     "shadow-ai",
			Severity: "HIGH",
			Message:  "Shadow AI detected",
		})
	}

	// mock logic for sector tripwires
	anomalies = append(anomalies, Anomaly{
		Type:     "proximity-healthcare",
		Severity: "CRITICAL",
		Message:  "Sector tripwire detected: Healthcare",
	})

	report := AnomalyReport{
		Clean:           len(anomalies) == 0,
		HighestSeverity: "CRITICAL",
		Anomalies:       anomalies,
		EvaluatedAt:     time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (e *Engine) HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "ok", "service": "airom-anomaly-engine"}`))
}
