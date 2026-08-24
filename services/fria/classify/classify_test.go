package classify

import (
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestClassify_AnnexIII_HighRisk_HR(t *testing.T) {
	engine := NewEngine()

	res := engine.ClassifySystem("Automated Talent Screener", "recruitment_workforce_hr", nil)
	if res.Tier != TierHighRisk {
		t.Errorf("expected High Risk tier, got %s", res.Tier)
	}
	if res.AnnexIIICategory == nil || *res.AnnexIIICategory != AnnexIII_4_EmploymentHR {
		t.Errorf("expected Annex III.4 category, got %+v", res.AnnexIIICategory)
	}
	if len(res.MandatoryActions) < 5 {
		t.Errorf("expected comprehensive mandatory actions list, got %d", len(res.MandatoryActions))
	}
}

func TestClassify_Article5_Prohibited(t *testing.T) {
	engine := NewEngine()

	res := engine.ClassifySystem("Citizen Behavior Ranker", "social_scoring_platform", nil)
	if res.Tier != TierUnacceptableRisk {
		t.Errorf("expected Unacceptable Risk tier, got %s", res.Tier)
	}
}

func TestClassify_Article50_Generative(t *testing.T) {
	engine := NewEngine()

	inv := &airom.Inventory{
		Components: []airom.Component{
			{ID: "c1", Kind: airom.KindHostedLLM, Name: "gpt-4o"},
		},
	}

	res := engine.ClassifySystem("Customer Support Bot", "general_customer_support", inv)
	if res.Tier != TierSpecificTransparency {
		t.Errorf("expected Specific Transparency tier for generative LLM, got %s", res.Tier)
	}
}

func TestClassify_MinimalRisk(t *testing.T) {
	engine := NewEngine()

	res := engine.ClassifySystem("Inventory Optimization Rule Engine", "supply_chain_logistics", nil)
	if res.Tier != TierMinimalRisk {
		t.Errorf("expected Minimal Risk tier, got %s", res.Tier)
	}
}
