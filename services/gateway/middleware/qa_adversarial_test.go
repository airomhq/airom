package middleware

import (
	"context"
	"fmt"
	"testing"

	"github.com/airomhq/airom/services/gateway/dlp"
	"github.com/airomhq/airom/services/gateway/watermark"
)

func TestQA_AdversarialModelPanicRecovery(t *testing.T) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionMask},
		watermark.DefaultWatermarkConfig("key"),
	)

	req := InterceptRequest{
		SessionID: "s-panic",
		Model:     "gpt-4o",
		Prompt:    "Harmless prompt",
	}

	_, err := pipeline.Intercept(context.Background(), req, func(p string) (string, error) {
		return "", fmt.Errorf("upstream 503 service unavailable")
	})

	if err == nil {
		t.Fatalf("expected error from failed upstream model call")
	}
}

func TestQA_AdversarialEmptyPayloads(t *testing.T) {
	pipeline := NewPipeline(
		dlp.DLPPolicy{DefaultAction: dlp.ActionMask},
		watermark.DefaultWatermarkConfig("key"),
	)

	req := InterceptRequest{
		SessionID: "s-empty",
		Model:     "gpt-4o",
		Prompt:    "",
	}

	resp, err := pipeline.Intercept(context.Background(), req, func(p string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("failed with empty payload: %v", err)
	}

	if resp.Completion != "" {
		t.Errorf("expected empty completion")
	}
}
