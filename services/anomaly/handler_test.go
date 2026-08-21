package anomaly

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestHealthzHandler(t *testing.T) {
	engine := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	engine.HealthzHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", res.StatusCode)
	}

	expected := `{"status": "ok", "service": "airom-anomaly-engine"}`
	if w.Body.String() != expected {
		t.Errorf("expected body %v, got %v", expected, w.Body.String())
	}
}

func TestEvaluateHandler_Success(t *testing.T) {
	engine := NewEngine()
	reqBody := EvaluateRequest{
		RepoID:     "repo1",
		BaseCommit: "commit1",
		HeadCommit: "commit2",
		BaseAIBOM: airom.Inventory{
			Components: []airom.Component{
				{Name: "model1"},
			},
		},
		HeadAIBOM: airom.Inventory{
			Components: []airom.Component{
				{Name: "model1"},
				{Name: "model2"},
			},
		},
		ManifestYAML: "test: true",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/anomaly/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	engine.EvaluateHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got %v", res.StatusCode)
	}

	var report AnomalyReport
	json.NewDecoder(w.Body).Decode(&report)
	
	shadowFound := false
	tripwireFound := false
	for _, anomaly := range report.Anomalies {
		if anomaly.Type == "shadow-ai" {
			shadowFound = true
		}
		if anomaly.Type == "proximity-healthcare" {
			tripwireFound = true
		}
	}

	if !shadowFound {
		t.Errorf("expected shadow AI detected")
	}
	if !tripwireFound {
		t.Errorf("expected sector tripwire detected")
	}
}

func TestEvaluateHandler_MalformedJSON(t *testing.T) {
	engine := NewEngine()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/anomaly/evaluate", bytes.NewReader([]byte("{malformed: true")))
	w := httptest.NewRecorder()

	engine.EvaluateHandler(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status Bad Request, got %v", res.StatusCode)
	}
}

func BenchmarkEvaluateHandler(b *testing.B) {
	engine := NewEngine()
	reqBody := EvaluateRequest{
		RepoID:     "repo1",
		BaseCommit: "commit1",
		HeadCommit: "commit2",
		BaseAIBOM: airom.Inventory{
			Components: []airom.Component{{Name: "model1"}},
		},
		HeadAIBOM: airom.Inventory{
			Components: []airom.Component{{Name: "model1"}, {Name: "model2"}},
		},
		ManifestYAML: "test: true",
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/anomaly/evaluate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		engine.EvaluateHandler(w, req)
	}
}
