package poa

import (
	"testing"
	"time"
)

func TestPOA_SingleAgentPaymentWithinLimit(t *testing.T) {
	gate := NewGate()

	gate.RegisterGrant(POAGrant{
		AgentID:              "agent-procurement",
		PrincipalOrg:         "Enterprise-Corp",
		AuthorizedScopes:     []POAScope{ScopeFinancialPayment},
		PerTransactionMaxUSD: 5000.0,
		DualCustodyThreshold: 1000.0,
		ValidUntil:           time.Now().UTC().Add(24 * time.Hour),
	})

	// $500 payment (under $1000 threshold) -> Approved without co-signer
	dec1 := gate.EvaluateAction(ActionRequest{
		RequestID: "req-1",
		AgentID:   "agent-procurement",
		Scope:     ScopeFinancialPayment,
		AmountUSD: 500.0,
	})

	if !dec1.Approved || dec1.RequiresCoSigner {
		t.Errorf("expected automatic approval for $500: %+v", dec1)
	}
}

func TestPOA_DualCustodyRequirement(t *testing.T) {
	gate := NewGate()

	gate.RegisterGrant(POAGrant{
		AgentID:              "agent-procurement",
		PrincipalOrg:         "Enterprise-Corp",
		AuthorizedScopes:     []POAScope{ScopeFinancialPayment},
		PerTransactionMaxUSD: 5000.0,
		DualCustodyThreshold: 1000.0,
	})

	// $2,500 payment without co-signer -> RequiresCoSigner
	dec1 := gate.EvaluateAction(ActionRequest{
		RequestID: "req-2",
		AgentID:   "agent-procurement",
		Scope:     ScopeFinancialPayment,
		AmountUSD: 2500.0,
	})

	if dec1.Approved || !dec1.RequiresCoSigner {
		t.Errorf("expected co-signer requirement for $2,500: %+v", dec1)
	}

	// $2,500 payment WITH human co-signer -> Approved
	dec2 := gate.EvaluateAction(ActionRequest{
		RequestID:     "req-3",
		AgentID:       "agent-procurement",
		Scope:         ScopeFinancialPayment,
		AmountUSD:     2500.0,
		HumanCoSigner: "treasury-officer-alice",
	})

	if !dec2.Approved {
		t.Errorf("expected approved with valid co-signer: %+v", dec2)
	}
}

func TestPOA_ScopeMismatch(t *testing.T) {
	gate := NewGate()

	gate.RegisterGrant(POAGrant{
		AgentID:          "agent-readonly",
		AuthorizedScopes: []POAScope{ScopeCustomerCommit},
	})

	dec := gate.EvaluateAction(ActionRequest{
		RequestID: "req-4",
		AgentID:   "agent-readonly",
		Scope:     ScopeInfraWrite, // Unauthorized
	})

	if dec.Approved {
		t.Errorf("expected rejection on unauthorized scope")
	}
}
