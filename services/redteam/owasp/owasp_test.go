package owasp

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestOWASPAuditor_CleanInventory(t *testing.T) {
	auditor := NewAuditor()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{
				ID:   "c1",
				Kind: airom.KindHostedLLM,
				Name: "gpt-4o",
				Model: &airom.ModelFacet{
					GenerationParams: []airom.BoundParam{{Name: "max_tokens", Value: "1024"}},
				},
			},
		},
	}

	scorecard := auditor.Audit(inv)
	if scorecard.TotalFindings != 0 {
		t.Errorf("expected 0 findings for clean inventory, got %d", scorecard.TotalFindings)
	}
	if scorecard.RiskScore != 0.0 {
		t.Errorf("expected 0.0 risk score, got %f", scorecard.RiskScore)
	}
}

func TestOWASPAuditor_PickleAndUnboundedRisks(t *testing.T) {
	auditor := NewAuditor()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{
				ID:   "c1",
				Kind: airom.KindLocalModelFile,
				Name: "vulnerable_model.pkl",
				Risks: []airom.ArtifactRisk{
					{
						ID:       airom.RiskPickleImport,
						Severity: airom.RiskHigh,
						Detail:   []string{"os.system"},
					},
				},
			},
			{
				ID:   "c2",
				Kind: airom.KindInfra,
				Name: "mcp-filesystem-server",
			},
			{
				ID:   "c3",
				Kind: airom.KindHostedLLM,
				Name: "claude-3-5",
				Model: &airom.ModelFacet{
					GenerationParams: []airom.BoundParam{{Name: "temperature", Value: "0.7"}}, // missing max_tokens
				},
			},
		},
	}

	scorecard := auditor.Audit(inv)
	if scorecard.TotalFindings < 3 {
		t.Fatalf("expected at least 3 findings, got %d", scorecard.TotalFindings)
	}

	if scorecard.CategoryPassMap[LLM03_SupplyChain] {
		t.Errorf("expected LLM03 to fail on pickle risk")
	}
	if scorecard.CategoryPassMap[LLM06_ExcessiveAgency] {
		t.Errorf("expected LLM06 to fail on tool server")
	}
	if scorecard.CategoryPassMap[LLM10_UnboundedConsumption] {
		t.Errorf("expected LLM10 to fail on missing max_tokens")
	}
}
