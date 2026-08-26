package logic

import (
	"testing"
)

func TestQA_AdversarialCaseAndWhitespaceEvasion(t *testing.T) {
	verifier := NewVerifier()

	evasivePlan := AgentActionPlan{
		PlanID:     "evasion-1",
		ActionVerb: "  drop_database \t\n",
	}

	res := verifier.ProvePlan(evasivePlan)
	if res.AxiomHolds {
		t.Fatalf("SECURITY VIOLATION: mixed-case whitespace-padded prohibited verb evaded logic verification")
	}
}

func TestQA_AdversarialNegativeCost(t *testing.T) {
	verifier := NewVerifier()

	plan := AgentActionPlan{
		PlanID:        "neg-cost",
		ActionVerb:    "FETCH",
		EstimatedCost: -1000.0,
		IsAuthSigned:  true,
	}

	res := verifier.ProvePlan(plan)
	if !res.AxiomHolds {
		t.Fatalf("expected harmless negative cost fetch to pass")
	}
}
