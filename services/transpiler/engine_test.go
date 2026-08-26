package transpiler

import (
	"testing"
)

func TestTranspiler_CDXToSPDX3(t *testing.T) {
	engine := NewEngine()

	cdxPayload := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": [
			{"name": "meta-llama/Llama-3-8B", "type": "machine-learning-model"}
		]
	}`)

	res, err := engine.Transpile(TranspileRequest{
		SourceFormat: FormatCycloneDX,
		TargetFormat: FormatSPDX3,
		Payload:      cdxPayload,
	})
	if err != nil {
		t.Fatalf("transpilation failed: %v", err)
	}

	if res.ComponentsRead != 1 || len(res.OutputPayload) == 0 {
		t.Errorf("unexpected transpilation result: %+v", res)
	}
}

func TestTranspiler_EmptyPayloadFails(t *testing.T) {
	engine := NewEngine()

	_, err := engine.Transpile(TranspileRequest{
		SourceFormat: FormatCycloneDX,
		TargetFormat: FormatSPDX3,
		Payload:      nil,
	})
	if err == nil {
		t.Fatalf("expected error on nil payload")
	}
}
