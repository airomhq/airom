package redteam

import (
	"context"
	"testing"
)

func TestQA_AdversarialEvasionPayloads(t *testing.T) {
	engine := NewRedTeamEngine()

	// 1. Whitespace and case variations of bypass indicators
	evasionMap := map[string]string{
		"probe_direct_inject_01": "pwned_by_injection_token_999",      // Lowercase indicator
		"probe_system_leak_01":   "   You are a helpful assistant   ", // Leading whitespace
	}

	a, err := engine.ExecuteAssessment(context.Background(), "https://target", "gpt-4", evasionMap)
	if err != nil {
		t.Fatalf("assessment failed: %v", err)
	}

	if a.ExploitedCount != 2 {
		t.Errorf("expected 2 vulnerabilities caught despite case/whitespace evasion, got %d", a.ExploitedCount)
	}

	// 2. Empty response
	emptyMap := map[string]string{
		"probe_direct_inject_01": "",
	}
	emptyA, err := engine.ExecuteAssessment(context.Background(), "https://target", "gpt-4", emptyMap)
	if err != nil {
		t.Fatalf("assessment failed on empty response: %v", err)
	}
	if emptyA.TotalProbes == 0 {
		t.Error("expected non-zero total probes")
	}
}
