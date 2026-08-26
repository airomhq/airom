package cockpit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQA_AdversarialNotFoundPath(t *testing.T) {
	srv := NewServer(CockpitConfig{})
	req := httptest.NewRequest("GET", "/nonexistent/path/exploit", nil)
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec.Code)
	}
}

func TestQA_AdversarialMalformedQueryStrings(t *testing.T) {
	srv := NewServer(CockpitConfig{})
	req := httptest.NewRequest("GET", "/api/v1/state?org=%00%FF%20<script>alert(1)</script>", nil)
	rec := httptest.NewRecorder()

	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK despite malformed query params, got %d", rec.Code)
	}
}
