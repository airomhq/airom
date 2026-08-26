package selfheal

import (
	"testing"
)

func TestQA_AdversarialReDoSNestedPatterns(t *testing.T) {
	compiler := NewCompiler()

	// Malicious regex intended to cause exponential catastrophic backtracking if unescaped
	maliciousInc := ZeroDayIncident{
		IncidentID:    "inc-redos",
		TriggerPhrase: "((((((a+)+)+)+)+)+)b",
	}

	patch, err := compiler.CompilePatch(maliciousInc)
	if err != nil || patch == nil {
		t.Fatalf("expected safe quoted compilation: %v", err)
	}

	// Must be treated as pure literal string
	if !patch.ReDoSSafe {
		t.Fatalf("expected ReDoSSafe flag true")
	}
}

func TestQA_AdversarialEmptyIncident(t *testing.T) {
	compiler := NewCompiler()

	patch, err := compiler.CompilePatch(ZeroDayIncident{})
	if err != nil || patch == nil {
		t.Fatalf("expected valid patch on empty incident: %v", err)
	}
}
