package structured

import (
	"testing"
)

func TestStructured_InstructorPasses(t *testing.T) {
	detector := NewDetector()

	spec := StructuredCallSpec{
		EngineType:        EngineInstructor,
		SchemaName:        "InvoiceExtractionSchema",
		HasTypeValidation: true,
		EnforcesGrammar:   false,
		MaxRetries:        3,
	}

	res := detector.EvaluateCall(spec)
	if !res.IsGuaranteed || len(res.Violations) != 0 {
		t.Fatalf("expected guaranteed schema, got violations: %+v", res.Violations)
	}

	if res.Component == nil || res.Component.Name != "INSTRUCTOR-Schema-InvoiceExtractionSchema" {
		t.Errorf("unexpected component generated: %+v", res.Component)
	}
}

func TestStructured_UnvalidatedSchemaFails(t *testing.T) {
	detector := NewDetector()

	unsafeSpec := StructuredCallSpec{
		EngineType:        EngineJSONSchema,
		SchemaName:        "RawLooseDict",
		HasTypeValidation: false, // Missing formal validator
		MaxRetries:        0,
	}

	res := detector.EvaluateCall(unsafeSpec)
	if res.IsGuaranteed || len(res.Violations) < 2 {
		t.Fatalf("expected unvalidated schema to fail with at least 2 violations, got %d", len(res.Violations))
	}
}
