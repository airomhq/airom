package prober

import (
	"strings"
	"testing"
)

func TestProber_GenerateAllOWASPCategories(t *testing.T) {
	generator := NewGenerator()
	probes := generator.GenerateProbes(50)

	if len(probes) != 50 {
		t.Fatalf("expected 50 generated probes, got %d", len(probes))
	}

	seenCategories := make(map[OWASPCategory]bool)
	for _, p := range probes {
		seenCategories[p.Category] = true
		if p.ProbeID == "" || p.PromptText == "" {
			t.Errorf("invalid probe structure: %+v", p)
		}
	}

	if len(seenCategories) < 10 {
		t.Errorf("expected all 10 OWASP categories covered, covered %d", len(seenCategories))
	}
}

func TestProber_ObfuscationStyles(t *testing.T) {
	generator := NewGenerator()
	probes := generator.GenerateProbes(4)

	for _, p := range probes {
		switch p.Obfuscation {
		case StyleBase64:
			if !strings.HasPrefix(p.PromptText, "BASE64:") {
				t.Errorf("expected BASE64 prefix")
			}
		case StyleLeetSpeak:
			if strings.Contains(p.PromptText, "e") {
				t.Errorf("leetspeak failed to replace 'e' character")
			}
		}
	}
}
