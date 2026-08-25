package pdf

import (
	"bytes"
	"testing"
	"time"
)

func TestPDF_GenerateValidDocument(t *testing.T) {
	generator := NewGenerator()

	spec := DocumentSpec{
		Title:            "AIROM Executive Compliance Dossier",
		OrganizationName: "Acme Autonomous AI",
		RepositoryName:   "acme/llm-pipeline",
		CommitSHA:        "abcdef123456",
		FrameworkName:    "EU AI Act Title III",
		ExecutiveSummary: "High-risk AEDT deployment conformant with Annex IV documentation.",
		TotalComponents:  14,
		ControlsMet:      12,
		GapsIdentified:   2,
		SignerName:       "Jane Doe",
		SignerTitle:      "Chief Compliance Officer",
		GeneratedAt:      time.Now().UTC(),
		Sections: []DocumentSection{
			{Heading: "1. Model Lineage", Content: "Lineage tracked from Meta LLaMA 3."},
		},
	}

	result := generator.GeneratePDF(spec)
	if result == nil || len(result.PDFBytes) == 0 {
		t.Fatalf("expected non-empty PDF result")
	}

	// 1. Verify PDF header
	if !bytes.HasPrefix(result.PDFBytes, []byte("%PDF-1.7")) {
		t.Errorf("missing PDF 1.7 header")
	}

	// 2. Verify EOF trailer
	if !bytes.HasSuffix(bytes.TrimSpace(result.PDFBytes), []byte("%%EOF")) {
		t.Errorf("missing %%EOF trailer")
	}

	// 3. Verify xref table
	if !bytes.Contains(result.PDFBytes, []byte("xref")) {
		t.Errorf("missing xref table in PDF stream")
	}
}

func TestPDF_TextEscaping(t *testing.T) {
	generator := NewGenerator()
	spec := DocumentSpec{
		Title:            "Special (Characters) \\ Test",
		ExecutiveSummary: "Testing (nested (parentheses)) and \\backslashes\\",
	}

	result := generator.GeneratePDF(spec)
	if result == nil || len(result.PDFBytes) == 0 {
		t.Fatalf("expected valid escaped PDF result")
	}
}
