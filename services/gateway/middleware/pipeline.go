package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/airomhq/airom/services/gateway/dlp"
	"github.com/airomhq/airom/services/gateway/watermark"
)

// Pipeline executes full-duplex security and governance middleware.
type Pipeline struct {
	dlpEngine  *dlp.Engine
	wmDetector *watermark.Detector
}

// NewPipeline constructs an interception pipeline.
func NewPipeline(dlpPolicy dlp.DLPPolicy, wmConfig watermark.WatermarkConfig) *Pipeline {
	return &Pipeline{
		dlpEngine:  dlp.NewEngine(dlpPolicy),
		wmDetector: watermark.NewDetector(wmConfig),
	}
}

// Intercept executes inbound DLP inspection and outbound governance.
func (p *Pipeline) Intercept(ctx context.Context, req InterceptRequest, modelFunc func(prompt string) (string, error)) (InterceptResponse, error) {
	start := time.Now()

	// 1. Inbound DLP Scrubbing
	dlpRes := p.dlpEngine.ScrubText(req.Prompt)
	if dlpRes.Blocked {
		return InterceptResponse{
			SessionID:      req.SessionID,
			Model:          req.Model,
			Completion:     dlpRes.SanitizedText,
			DLP:            dlpRes,
			ProcessingTime: time.Since(start),
		}, fmt.Errorf("inbound request blocked by DLP policy")
	}

	// 2. Upstream Model Execution
	completion, err := modelFunc(dlpRes.SanitizedText)
	if err != nil {
		return InterceptResponse{
			SessionID:      req.SessionID,
			Model:          req.Model,
			ProcessingTime: time.Since(start),
		}, err
	}

	// 3. Outbound Watermark Verification
	wmRes := p.wmDetector.Detect(completion)

	return InterceptResponse{
		SessionID:         req.SessionID,
		Model:             req.Model,
		Completion:        completion,
		DLP:               dlpRes,
		WatermarkDetected: &wmRes,
		ProcessingTime:    time.Since(start),
	}, nil
}
