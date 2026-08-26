package cockpit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCockpit_IndexHTML(t *testing.T) {
	srv := NewServer(CockpitConfig{Organization: "TestOrg"})
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	body := rec.Body.String()
	if body == "" {
		t.Fatalf("expected HTML body")
	}
}

func TestCockpit_StateJSON(t *testing.T) {
	srv := NewServer(CockpitConfig{Organization: "TestOrg"})
	req := httptest.NewRequest("GET", "/api/v1/state", nil)
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var state CockpitState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("failed to decode state JSON: %v", err)
	}

	if state.Organization != "TestOrg" {
		t.Errorf("unexpected org name: %s", state.Organization)
	}
}

func TestCockpit_PushEvent(t *testing.T) {
	srv := NewServer(CockpitConfig{})
	srv.PushEvent(CockpitEvent{
		EventID: "evt-1",
		Type:    "REGWATCH_ALERT",
		Message: "New statute passed",
	})

	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var events []CockpitEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil || len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}
