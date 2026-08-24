package proto

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/airomhq/airom/internal/plugin"
	"github.com/airomhq/airom/pkg/airom"
)

func TestDetectorAdapter_Dispatch(t *testing.T) {
	transport := plugin.NewTransport("secret")

	// Register mock plugin handler
	transport.RegisterMethod("detector.detect", func(req plugin.PluginMessage) plugin.PluginMessage {
		var dReq DetectRequest
		_ = json.Unmarshal(req.Payload, &dReq)

		resp := DetectResponse{
			Components: []airom.Component{
				{
					ID:       "plugin:comp_1",
					Kind:     airom.KindHostedLLM,
					Name:     "custom-proprietary-model",
					Provider: airom.KnownString("internal-ai"),
				},
			},
		}
		b, _ := json.Marshal(resp)
		return plugin.PluginMessage{ID: req.ID, Method: req.Method, Payload: b}
	})

	adapter := NewDetectorAdapter(transport)
	req := DetectRequest{
		SessionID: "s1",
		FilePath:  "src/inference.py",
		Content:   []byte("model = load_custom_llm()"),
		Language:  "python",
	}

	resp, err := adapter.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	if len(resp.Components) != 1 || resp.Components[0].Name != "custom-proprietary-model" {
		t.Errorf("unexpected components: %+v", resp.Components)
	}
}

func TestWriterAdapter_Dispatch(t *testing.T) {
	transport := plugin.NewTransport("secret")

	transport.RegisterMethod("writer.write", func(req plugin.PluginMessage) plugin.PluginMessage {
		resp := WriteResponse{
			Output: []byte("<custom_xml_aibom></custom_xml_aibom>"),
		}
		b, _ := json.Marshal(resp)
		return plugin.PluginMessage{ID: req.ID, Method: req.Method, Payload: b}
	})

	adapter := NewWriterAdapter(transport)
	req := WriteRequest{
		SessionID: "s2",
		Format:    "custom-xml",
		Inventory: &airom.Inventory{},
	}

	out, err := adapter.Write(context.Background(), req)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if string(out) != "<custom_xml_aibom></custom_xml_aibom>" {
		t.Errorf("output mismatch: %s", string(out))
	}
}
