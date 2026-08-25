package pdf

import (
	"strings"
	"testing"
)

func TestQA_AdversarialHugeTextPayload(t *testing.T) {
	generator := NewGenerator()
	largeSummary := strings.Repeat("Extremely large technical documentation paragraph with audit disclosures. ", 500)

	spec := DocumentSpec{
		Title:            "Large Payload PDF",
		ExecutiveSummary: largeSummary,
	}

	result := generator.GeneratePDF(spec)
	if result == nil || len(result.PDFBytes) == 0 {
		t.Fatalf("expected valid PDF on large payload")
	}
}

func TestQA_AdversarialEmptyDocumentSpec(t *testing.T) {
	generator := NewGenerator()
	spec := DocumentSpec{}

	result := generator.GeneratePDF(spec)
	if result == nil || len(result.PDFBytes) == 0 {
		t.Fatalf("expected valid PDF on empty spec")
	}
}
