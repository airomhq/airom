package circuit

import (
	"errors"
	"testing"
)

func TestCircuit_NormalAllowedCalls(t *testing.T) {
	ceilings := SafetyCeilings{MaxHopDepth: 5, MaxDriftThreshold: 0.80, MaxCostCeilingUSD: 10.0, MaxTotalMessages: 50}
	breaker := NewBreaker(ceilings)

	call := DelegationCall{CurrentHop: 1, DriftScore: 0.10, CostDelta: 0.50}
	if err := breaker.AllowDelegation(call); err != nil {
		t.Fatalf("expected allowed delegation, got %v", err)
	}

	status := breaker.Status()
	if status.State != StateClosed || status.AccumulatedCost != 0.50 {
		t.Errorf("unexpected status: %+v", status)
	}
}

func TestCircuit_HopDepthTrip(t *testing.T) {
	ceilings := SafetyCeilings{MaxHopDepth: 3}
	breaker := NewBreaker(ceilings)

	// Hop 1, 2, 3 allowed
	for hop := 1; hop <= 3; hop++ {
		if err := breaker.AllowDelegation(DelegationCall{CurrentHop: hop}); err != nil {
			t.Fatalf("unexpected error at hop %d", hop)
		}
	}

	// Hop 4 trips breaker
	err := breaker.AllowDelegation(DelegationCall{CurrentHop: 4})
	if err == nil || !errors.Is(err, ErrCircuitTripped) {
		t.Fatalf("expected ErrCircuitTripped at hop 4")
	}

	if breaker.Status().State != StateOpen {
		t.Errorf("expected circuit state OPEN")
	}
}

func TestCircuit_GoalDriftTrip(t *testing.T) {
	ceilings := SafetyCeilings{MaxDriftThreshold: 0.70}
	breaker := NewBreaker(ceilings)

	call := DelegationCall{CurrentHop: 1, DriftScore: 0.95}
	err := breaker.AllowDelegation(call)
	if err == nil {
		t.Fatalf("expected error on severe goal drift")
	}
}

func TestCircuit_CostCeilingTrip(t *testing.T) {
	ceilings := SafetyCeilings{MaxCostCeilingUSD: 5.0}
	breaker := NewBreaker(ceilings)

	_ = breaker.AllowDelegation(DelegationCall{CostDelta: 3.0})
	err := breaker.AllowDelegation(DelegationCall{CostDelta: 3.0}) // Total = 6.0 > 5.0

	if err == nil {
		t.Fatalf("expected cost ceiling error")
	}
}
