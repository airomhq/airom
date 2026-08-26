package structured

import (
	"testing"
)

func TestQA_AdversarialNegativeRetries(t *testing.T) {
	detector := NewDetector()

	negSpec := StructuredCallSpec{
		EngineType:        EngineInstructor,
		SchemaName:        "NegSchema",
		HasTypeValidation: true,
		MaxRetries:        -10,
	}

	res := detector.EvaluateCall(negSpec)
	if res.Component == nil {
		t.Fatalf("expected component returned on negative retries")
	}
}

func TestQA_AdversarialWeirdSchemaNames(t *testing.T) {
	detector := NewDetector()

	weirdSpec := StructuredCallSpec{
		EngineType:        EngineOutlines,
		SchemaName:        "  <Schema.With.Dots & Slashes / #00>  ",
		HasTypeValidation: true,
		EnforcesGrammar:   true,
	}

	res := detector.EvaluateCall(weirdSpec)
	if !res.IsGuaranteed || res.Component == nil {
		t.Fatalf("expected clean sanitized component for weird schema name")
	}
}
