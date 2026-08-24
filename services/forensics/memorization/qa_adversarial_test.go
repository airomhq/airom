package memorization

import (
	"strings"
	"testing"
)

func TestQA_AdversarialEmptyAndWhitespaceProbes(t *testing.T) {
	auditor := NewAuditor()

	// Empty probe
	probeEmpty := CanaryProbe{}
	_, detected := auditor.EvaluateExtraction(probeEmpty, "")
	if detected {
		t.Errorf("empty probe should not trigger detection")
	}

	// Whitespace only
	probeSpace := CanaryProbe{ExpectedTail: "    "}
	_, detected = auditor.EvaluateExtraction(probeSpace, "   ")
	if detected {
		t.Errorf("whitespace probe should not trigger detection")
	}
}

func TestQA_AdversarialExtremeStringOverlap(t *testing.T) {
	auditor := NewAuditor()

	hugeTail := strings.Repeat("confidential_medical_dataset_record_string_", 1000)
	probe := CanaryProbe{
		ID:           "huge-canary",
		ExpectedTail: hugeTail,
	}

	finding, detected := auditor.EvaluateExtraction(probe, hugeTail)
	if !detected || finding.VerbatimOverlap != 1.0 {
		t.Errorf("failed detecting huge canary: %+v", finding)
	}
}
