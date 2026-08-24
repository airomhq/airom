package circuit

import (
	"errors"
	"testing"
)

func TestQA_AdversarialOpenCircuitRejections(t *testing.T) {
	ceilings := SafetyCeilings{MaxHopDepth: 2}
	breaker := NewBreaker(ceilings)

	// Trip circuit
	_ = breaker.AllowDelegation(DelegationCall{CurrentHop: 5})

	// 100 subsequent calls must be rejected
	for i := 0; i < 100; i++ {
		err := breaker.AllowDelegation(DelegationCall{CurrentHop: 1})
		if err == nil || !errors.Is(err, ErrCircuitTripped) {
			t.Fatalf("expected rejection while circuit is OPEN at iter %d", i)
		}
	}
}

func TestQA_AdversarialResetWorkflow(t *testing.T) {
	ceilings := SafetyCeilings{MaxHopDepth: 2}
	breaker := NewBreaker(ceilings)

	_ = breaker.AllowDelegation(DelegationCall{CurrentHop: 5})
	if breaker.Status().State != StateOpen {
		t.Fatalf("expected state OPEN")
	}

	// Reset breaker
	breaker.Reset()
	if breaker.Status().State != StateClosed {
		t.Fatalf("expected state CLOSED after reset")
	}

	// Normal calls work again
	err := breaker.AllowDelegation(DelegationCall{CurrentHop: 1})
	if err != nil {
		t.Fatalf("expected allowed delegation after reset, got %v", err)
	}
}
