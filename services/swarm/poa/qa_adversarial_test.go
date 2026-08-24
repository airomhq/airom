package poa

import (
	"testing"
	"time"
)

func TestQA_AdversarialNegativeAmounts(t *testing.T) {
	gate := NewGate()
	gate.RegisterGrant(POAGrant{
		AgentID:          "agent-attacker",
		AuthorizedScopes: []POAScope{ScopeFinancialPayment},
	})

	dec := gate.EvaluateAction(ActionRequest{
		AgentID:   "agent-attacker",
		Scope:     ScopeFinancialPayment,
		AmountUSD: -500.0, // Negative amount exploit
	})

	if dec.Approved {
		t.Fatalf("security vulnerability: negative transaction approved")
	}
}

func TestQA_AdversarialExpiredGrant(t *testing.T) {
	gate := NewGate()
	gate.RegisterGrant(POAGrant{
		AgentID:          "agent-expired",
		AuthorizedScopes: []POAScope{ScopeFinancialPayment},
		ValidUntil:       time.Now().UTC().Add(-1 * time.Hour), // Expired 1 hour ago
	})

	dec := gate.EvaluateAction(ActionRequest{
		AgentID:   "agent-expired",
		Scope:     ScopeFinancialPayment,
		AmountUSD: 100.0,
	})

	if dec.Approved {
		t.Fatalf("security vulnerability: expired POA grant approved action")
	}
}
