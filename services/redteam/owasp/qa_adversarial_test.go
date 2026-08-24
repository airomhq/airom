package owasp

import (
	"fmt"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialNilAndSparseInventories(t *testing.T) {
	auditor := NewAuditor()

	// Nil inventory
	sc1 := auditor.Audit(nil)
	if sc1.TotalFindings != 0 {
		t.Errorf("expected 0 findings for nil inventory")
	}

	// Empty inventory
	sc2 := auditor.Audit(&airom.Inventory{})
	if sc2.TotalFindings != 0 {
		t.Errorf("expected 0 findings for empty inventory")
	}
}

func TestQA_AdversarialExtremeRiskArrays(t *testing.T) {
	auditor := NewAuditor()

	var risks []airom.ArtifactRisk
	for i := 0; i < 1000; i++ {
		risks = append(risks, airom.ArtifactRisk{
			ID:       airom.RiskID(fmt.Sprintf("AIROM-RISK-PICKLE-%d", i)),
			Severity: airom.RiskHigh,
			Detail:   []string{"pickle execution payload"},
		})
	}

	inv := &airom.Inventory{
		Components: []airom.Component{
			{
				ID:    "extreme-risks",
				Kind:  airom.KindLocalModelFile,
				Name:  "bomb.pkl",
				Risks: risks,
			},
		},
	}

	scorecard := auditor.Audit(inv)
	if scorecard.TotalFindings != 1000 {
		t.Fatalf("expected 1000 findings, got %d", scorecard.TotalFindings)
	}

	if scorecard.RiskScore == 0.0 {
		t.Errorf("expected non-zero risk score for extreme risks")
	}
}
