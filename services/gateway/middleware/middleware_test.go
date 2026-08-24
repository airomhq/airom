package middleware

import (
	"context"
	"strings"
	"testing"

	"github.com/airomhq/airom/services/gateway/dlp"
	"github.com/airomhq/airom/services/gateway/watermark"
)

func TestPipeline_CleanExecution(t *testing.T) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionMask},
		watermark.DefaultWatermarkConfig("key"),
	)

	req := InterceptRequest{
		SessionID: "s1",
		Model:     "gpt-4o",
		Prompt:    "User SSN is 123-45-6789. Summarize account.",
	}

	modelCalled := false
	resp, err := pipeline.Intercept(context.Background(), req, func(prompt string) (string, error) {
		modelCalled = true
		if !strings.Contains(prompt, "[REDACTED_SSN]") {
			t.Errorf("model received unredacted prompt: %s", prompt)
		}
		return "Account summary for user.", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !modelCalled {
		t.Errorf("expected model invoked")
	}

	if len(resp.DLP.Findings) != 1 {
		t.Errorf("expected 1 DLP finding, got %d", len(resp.DLP.Findings))
	}
}

func TestPipeline_InboundBlock(t *testing.T) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionBlock},
		watermark.DefaultWatermarkConfig("key"),
	)

	req := InterceptRequest{
		SessionID: "s2",
		Model:     "gpt-4o",
		Prompt:    "User SSN is 123-45-6789",
	}

	modelCalled := false
	_, err := pipeline.Intercept(context.Background(), req, func(prompt string) (string, error) {
		modelCalled = true
		return "response", nil
	})

	if err == nil {
		t.Fatalf("expected error on blocked request")
	}

	if modelCalled {
		t.Errorf("model should NOT be invoked on blocked request")
	}
}
