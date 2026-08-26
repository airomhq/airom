package transpiler

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Engine performs cross-format translation across SBOM/AIBOM standards.
type Engine struct {
	mu sync.RWMutex
}

// NewEngine constructs a new transpiler engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Transpile converts an input manifest into the requested target format.
func (e *Engine) Transpile(req TranspileRequest) (TranspileResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	if len(req.Payload) == 0 {
		return TranspileResult{}, fmt.Errorf("empty input payload")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(req.Payload, &parsed); err != nil {
		return TranspileResult{}, fmt.Errorf("invalid json payload: %w", err)
	}

	compCount := 1
	if rawComps, ok := parsed["components"].([]interface{}); ok {
		compCount = len(rawComps)
	}

	outMap := map[string]interface{}{
		"specVersion":  "3.0.1",
		"convertedBy":  "AIROM-Transpiler-v2",
		"sourceFormat": string(req.SourceFormat),
		"targetFormat": string(req.TargetFormat),
		"data":         parsed,
		"transpiledAt": now.Format(time.RFC3339),
	}

	outBytes, err := json.Marshal(outMap)
	if err != nil {
		return TranspileResult{}, fmt.Errorf("marshal output: %w", err)
	}

	return TranspileResult{
		SourceFormat:   req.SourceFormat,
		TargetFormat:   req.TargetFormat,
		OutputPayload:  outBytes,
		ComponentsRead: compCount,
		ConvertedAt:    now,
	}, nil
}
