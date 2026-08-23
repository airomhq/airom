package shadowai

import (
	"testing"
)

func TestQA_AdversarialShadowAIEvasion(t *testing.T) {
	detector := NewShadowAIDetector()

	adversarialFiles := []FileEntry{
		{
			Path:    "internal/secret/.env",
			Content: `  OPENAI_API_KEY   :   "sk-proj-019283746501928374650192837465"  `, // Extra whitespace & quotes
		},
		{
			Path:    "configs/anthropic.json",
			Content: `{"anthropic_api_key": "sk-ant-api03-01928374650192837465019283"}`, // JSON key-value
		},
		{
			Path:    "packages/app/very/deep/path/.cursorrules",
			Content: "Nested rule file", // Deep nested path
		},
		{
			Path:    "empty.txt",
			Content: "   \n\t  ", // Pure whitespace
		},
	}

	inv, err := detector.ScanFiles(adversarialFiles, DetectorOptions{OrganizationID: "org_evasion"})
	if err != nil {
		t.Fatalf("ScanFiles failed on adversarial inputs: %v", err)
	}

	if inv.TotalDiscovered != 3 {
		t.Errorf("expected 3 discoveries from adversarial files, got %d", inv.TotalDiscovered)
	}

	// Verify deduplication on duplicate occurrences in the same file
	duplicateFile := []FileEntry{
		{
			Path:    "dup.py",
			Content: "sk-proj-12345678901234567890123456\nsk-proj-12345678901234567890123456",
		},
	}
	dupInv, _ := detector.ScanFiles(duplicateFile, DetectorOptions{OrganizationID: "org_dup"})
	if dupInv.TotalDiscovered != 1 {
		t.Errorf("expected duplicate findings in single file to deduplicate to 1, got %d", dupInv.TotalDiscovered)
	}
}
