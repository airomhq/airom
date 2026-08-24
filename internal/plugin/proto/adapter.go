package proto

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airomhq/airom/internal/plugin"
)

// DetectorAdapter wraps an out-of-process detector plugin.
type DetectorAdapter struct {
	transport *plugin.Transport
}

// NewDetectorAdapter constructs a detector adapter.
func NewDetectorAdapter(t *plugin.Transport) *DetectorAdapter {
	return &DetectorAdapter{transport: t}
}

// Detect sends a file to the plugin detector over IPC.
func (a *DetectorAdapter) Detect(ctx context.Context, req DetectRequest) (*DetectResponse, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	msg := plugin.PluginMessage{
		ID:      req.SessionID,
		Method:  "detector.detect",
		Payload: payload,
	}

	respMsg, err := a.transport.Call(msg)
	if err != nil {
		return nil, fmt.Errorf("transport call: %w", err)
	}

	if respMsg.IsError {
		return nil, fmt.Errorf("plugin error: %s", respMsg.ErrorText)
	}

	var resp DetectResponse
	if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &resp, nil
}

// WriterAdapter wraps an out-of-process writer plugin.
type WriterAdapter struct {
	transport *plugin.Transport
}

// NewWriterAdapter constructs a writer adapter.
func NewWriterAdapter(t *plugin.Transport) *WriterAdapter {
	return &WriterAdapter{transport: t}
}

// Write invokes custom serialization on the plugin.
func (a *WriterAdapter) Write(ctx context.Context, req WriteRequest) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	msg := plugin.PluginMessage{
		ID:      req.SessionID,
		Method:  "writer.write",
		Payload: payload,
	}

	respMsg, err := a.transport.Call(msg)
	if err != nil {
		return nil, err
	}

	if respMsg.IsError {
		return nil, fmt.Errorf("writer plugin error: %s", respMsg.ErrorText)
	}

	var resp WriteResponse
	if err := json.Unmarshal(respMsg.Payload, &resp); err != nil {
		return nil, err
	}

	return resp.Output, nil
}
