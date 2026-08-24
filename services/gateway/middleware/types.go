// Package middleware provides unified interceptors for the AIROM Runtime Gateway
// combining DLP, policy clamping, and token watermarking (ARCHITECTURE.md §13).
package middleware

import (
	"time"

	"github.com/airomhq/airom/services/gateway/dlp"
	"github.com/airomhq/airom/services/gateway/watermark"
)

// InterceptRequest represents a prompt payload arriving at the gateway.
type InterceptRequest struct {
	SessionID string            `json:"sessionId"`
	Model     string            `json:"model"`
	Prompt    string            `json:"prompt"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// InterceptResponse represents the transformed output returned to the client.
type InterceptResponse struct {
	SessionID         string                        `json:"sessionId"`
	Model             string                        `json:"model"`
	Completion        string                        `json:"completion"`
	DLP               dlp.StreamResult              `json:"dlp"`
	WatermarkDetected *watermark.VerificationResult `json:"watermarkDetected,omitempty"`
	ProcessingTime    time.Duration                 `json:"processingTime"`
}
