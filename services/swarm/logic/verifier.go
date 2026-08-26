package logic

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Verifier formally proves that agent action plans satisfy corporate safety axioms.
type Verifier struct {
	mu     sync.RWMutex
	axioms []PredicateRule
}

// NewVerifier constructs a new formal logic verifier with baseline security axioms.
func NewVerifier() *Verifier {
	return &Verifier{
		axioms: []PredicateRule{
			{AxiomID: "AXIOM_NO_DESTRUCTIVE_SCHEMA", ForbiddenVerb: "DROP_DATABASE", MaxCostUSD: 100.0, RequiresAuth: true},
			{AxiomID: "AXIOM_NO_UNENCRYPTED_EXFIL", ForbiddenVerb: "EXPORT_RAW_PII", MaxCostUSD: 50.0, RequiresAuth: true},
			{AxiomID: "AXIOM_BUDGET_CAP", ForbiddenVerb: "PURCHASE_HARDWARE", MaxCostUSD: 500.0, RequiresAuth: true},
		},
	}
}

// ProvePlan verifies all predicates against an action plan.
func (v *Verifier) ProvePlan(plan AgentActionPlan) FormalProofResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	normVerb := strings.ToUpper(strings.TrimSpace(plan.ActionVerb))

	for _, ax := range v.axioms {
		// 1. Prohibit forbidden verbs
		if ax.ForbiddenVerb != "" && normVerb == ax.ForbiddenVerb {
			violations = append(violations, fmt.Sprintf("AXIOM VIOLATION [%s]: Prohibited action verb '%s'", ax.AxiomID, normVerb))
		}

		// 2. Budget limits
		if ax.MaxCostUSD > 0 && plan.EstimatedCost > ax.MaxCostUSD && !plan.IsAuthSigned {
			violations = append(violations, fmt.Sprintf("AXIOM VIOLATION [%s]: Estimated cost ($%.2f) exceeds $%.2f limit without cryptographic authorization", ax.AxiomID, plan.EstimatedCost, ax.MaxCostUSD))
		}

		// 3. Mandatory auth
		if ax.RequiresAuth && strings.Contains(normVerb, "ADMIN") && !plan.IsAuthSigned {
			violations = append(violations, fmt.Sprintf("AXIOM VIOLATION [%s]: Administrative verb requires signed authorization", ax.AxiomID))
		}
	}

	return FormalProofResult{
		PlanID:      plan.PlanID,
		AxiomHolds:  len(violations) == 0,
		Violations:  violations,
		EvaluatedAt: now,
	}
}
