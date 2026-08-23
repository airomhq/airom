package gateway

import (
	"testing"
)

func TestCircuitBreaker_LimitAndTrip(t *testing.T) {
	cb := NewCircuitBreaker(5)
	session := "session-agent-01"

	// Calls 1 to 5 should be allowed
	for i := 1; i <= 5; i++ {
		allowed, count := cb.Allow(session)
		if !allowed {
			t.Errorf("call %d should be allowed, got allowed=false", i)
		}
		if count != i {
			t.Errorf("expected count %d, got %d", i, count)
		}
	}

	// Call 6 should trip the breaker
	allowed6, _ := cb.Allow(session)
	if allowed6 {
		t.Error("call 6 should trip the breaker, but was allowed")
	}
	if !cb.IsTripped(session) {
		t.Error("circuit breaker should report IsTripped=true")
	}

	// Subsequent calls must continue to fail
	allowed7, _ := cb.Allow(session)
	if allowed7 {
		t.Error("subsequent call should be blocked while tripped")
	}

	// Resetting should clear tripped state
	cb.Reset(session)
	if cb.IsTripped(session) {
		t.Error("circuit breaker should not be tripped after Reset")
	}

	allowedNew, countNew := cb.Allow(session)
	if !allowedNew || countNew != 1 {
		t.Errorf("expected fresh call allowed after reset, got allowed=%v, count=%d", allowedNew, countNew)
	}
}
