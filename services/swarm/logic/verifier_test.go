package logic

import (
	"testing"
)

func TestLogic_BenignPlanPasses(t *testing.T) {
	verifier := NewVerifier()

	plan := AgentActionPlan{
		PlanID:         "plan-001",
		AgentID:        "research-agent-1",
		ActionVerb:     "READ_DOCUMENT",
		TargetResource: "docs/report.pdf",
		EstimatedCost:  0.05,
		IsAuthSigned:   true,
	}

	res := verifier.ProvePlan(plan)
	if !res.AxiomHolds || len(res.Violations) != 0 {
		t.Fatalf("expected benign plan to pass formal proof, got violations: %+v", res.Violations)
	}
}

func TestLogic_AxiomViolationFails(t *testing.T) {
	verifier := NewVerifier()

	unsafePlan := AgentActionPlan{
		PlanID:        "plan-danger",
		ActionVerb:    "DROP_DATABASE",
		EstimatedCost: 9999.0,
		IsAuthSigned:  false,
	}

	res := verifier.ProvePlan(unsafePlan)
	if res.AxiomHolds || len(res.Violations) < 2 {
		t.Fatalf("expected unsafe plan to fail with at least 2 axiom violations, got %d", len(res.Violations))
	}
}
