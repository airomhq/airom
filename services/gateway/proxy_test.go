package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxy_ApprovedModel_Succeeds(t *testing.T) {
	cfg := GatewayConfig{
		ApprovedModels: []string{"gpt-4o", "claude-3-5-sonnet"},
		MaxTemperature: 0.7,
		MaxTokens:      2048,
	}
	server := NewServer(cfg)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	payload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello AIROM"},
		},
		"temperature": 0.5,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestProxy_UnapprovedModel_BlockedWith403(t *testing.T) {
	cfg := GatewayConfig{
		ApprovedModels: []string{"gpt-4o", "claude-3-5-sonnet"},
	}
	server := NewServer(cfg)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	payload := map[string]interface{}{
		"model": "shadow-model-unvetted-99",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello unapproved model"},
		},
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden for unapproved model, got %d", resp.StatusCode)
	}
}

func TestProxy_RedactionAndCircuitBreaker_EndToEnd(t *testing.T) {
	cfg := GatewayConfig{
		ApprovedModels:                  []string{"gpt-4o"},
		EnableRedaction:                 true,
		CircuitBreakerMaxCallsPerMinute: 3,
	}
	server := NewServer(cfg)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	client := &http.Client{}

	// Send 3 requests with PII
	for i := 0; i < 3; i++ {
		payload := map[string]interface{}{
			"model": "gpt-4o",
			"messages": []map[string]string{
				{"role": "user", "content": "Customer with SSN 000-11-2222 and key AKIAIOSFODNN7EXAMPLE"},
			},
		}
		body, _ := json.Marshal(payload)

		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("X-Session-ID", "test-agent-sess")
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d expected status 200, got %d", i, resp.StatusCode)
		}
	}

	// 4th request should trip circuit breaker (limit 3)
	payload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": "Repeat loop"},
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("X-Session-ID", "test-agent-sess")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("4th request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests on tripped circuit breaker, got %d", resp.StatusCode)
	}
}

func TestProxy_MCPInvoke_Success(t *testing.T) {
	cfg := GatewayConfig{
		CircuitBreakerMaxCallsPerMinute: 10,
	}
	server := NewServer(cfg)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	payload := map[string]interface{}{
		"tool_name": "fetch_weather",
		"arguments": map[string]interface{}{"city": "Berlin"},
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(ts.URL+"/v1/mcp/invoke", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("mcp invoke failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}
