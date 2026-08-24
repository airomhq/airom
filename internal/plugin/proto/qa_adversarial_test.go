package proto

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/airomhq/airom/internal/plugin"
)

func TestQA_AdversarialPluginErrorPropagation(t *testing.T) {
	transport := plugin.NewTransport("secret")
	transport.RegisterMethod("detector.detect", func(req plugin.PluginMessage) plugin.PluginMessage {
		return plugin.PluginMessage{
			ID:        req.ID,
			IsError:   true,
			ErrorText: "custom plugin execution failed: permission denied",
		}
	})

	adapter := NewDetectorAdapter(transport)
	req := DetectRequest{SessionID: "s-err", FilePath: "f.py"}

	_, err := adapter.Detect(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error from plugin, got nil")
	}
}

func TestQA_AdversarialMalformedJSONResponse(t *testing.T) {
	transport := plugin.NewTransport("secret")
	transport.RegisterMethod("detector.detect", func(req plugin.PluginMessage) plugin.PluginMessage {
		return plugin.PluginMessage{
			ID:      req.ID,
			Payload: []byte("MALFORMED_JSON_{{{"),
		}
	})

	adapter := NewDetectorAdapter(transport)
	req := DetectRequest{SessionID: "s-corrupt", FilePath: "f.py"}

	_, err := adapter.Detect(context.Background(), req)
	if err == nil {
		t.Fatalf("expected JSON unmarshal error, got nil")
	}
}

func TestQA_AdversarialNilInventory(t *testing.T) {
	transport := plugin.NewTransport("secret")
	respBytes, _ := json.Marshal(WriteResponse{Output: []byte("OK")})
	transport.RegisterMethod("writer.write", func(req plugin.PluginMessage) plugin.PluginMessage {
		return plugin.PluginMessage{ID: req.ID, Payload: respBytes}
	})

	adapter := NewWriterAdapter(transport)
	req := WriteRequest{SessionID: "s-nil", Inventory: nil}

	out, err := adapter.Write(context.Background(), req)
	if err != nil || string(out) != "OK" {
		t.Fatalf("failed with nil inventory: %v", err)
	}
}
