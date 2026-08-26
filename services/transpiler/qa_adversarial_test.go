package transpiler

import (
	"testing"
)

func TestQA_AdversarialMalformedJSONPayload(t *testing.T) {
	engine := NewEngine()

	_, err := engine.Transpile(TranspileRequest{
		SourceFormat: FormatCycloneDX,
		TargetFormat: FormatSPDX3,
		Payload:      []byte(`{ "unclosed_json": `),
	})
	if err == nil {
		t.Fatalf("expected error on malformed JSON payload")
	}
}

func TestQA_AdversarialMassiveNestedPayload(t *testing.T) {
	engine := NewEngine()

	payload := []byte(`{"a":{"b":{"c":{"d":{"components":[{"name":"deep_model"}]}}}}}`)
	res, err := engine.Transpile(TranspileRequest{
		SourceFormat: FormatNativeJSON,
		TargetFormat: FormatCycloneDX,
		Payload:      payload,
	})
	if err != nil || len(res.OutputPayload) == 0 {
		t.Fatalf("expected successful conversion for nested JSON")
	}
}
