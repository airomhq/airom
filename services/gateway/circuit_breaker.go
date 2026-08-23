package gateway

import (
	"sync"
	"time"
)

// CircuitBreaker guards against autonomous agentic runaway execution loops and recursive tool calls.
type CircuitBreaker struct {
	mu            sync.Mutex
	maxCalls      int
	window        time.Duration
	sessionCalls  map[string][]time.Time
	trippedStates map[string]bool
}

// NewCircuitBreaker initializes a circuit breaker with a maximum calls-per-minute threshold.
func NewCircuitBreaker(maxCallsPerMinute int) *CircuitBreaker {
	if maxCallsPerMinute <= 0 {
		maxCallsPerMinute = 25
	}
	return &CircuitBreaker{
		maxCalls:      maxCallsPerMinute,
		window:        1 * time.Minute,
		sessionCalls:  make(map[string][]time.Time),
		trippedStates: make(map[string]bool),
	}
}

// Allow records a call for a given session and reports whether the call is permitted.
// If the call count within the sliding window exceeds the configured threshold, the breaker trips.
func (cb *CircuitBreaker) Allow(sessionID string) (bool, int) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if sessionID == "" {
		sessionID = "default"
	}

	if cb.trippedStates[sessionID] {
		return false, len(cb.sessionCalls[sessionID])
	}

	now := time.Now().UTC()
	cutoff := now.Add(-cb.window)

	// Filter timestamps within sliding window
	var active []time.Time
	for _, t := range cb.sessionCalls[sessionID] {
		if t.After(cutoff) {
			active = append(active, t)
		}
	}

	active = append(active, now)
	cb.sessionCalls[sessionID] = active

	if len(active) > cb.maxCalls {
		cb.trippedStates[sessionID] = true
		return false, len(active)
	}

	return true, len(active)
}

// IsTripped returns whether the circuit breaker is currently open (blocking) for a session.
func (cb *CircuitBreaker) IsTripped(sessionID string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if sessionID == "" {
		sessionID = "default"
	}
	return cb.trippedStates[sessionID]
}

// Reset clears the tripped state and call history for a session.
func (cb *CircuitBreaker) Reset(sessionID string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if sessionID == "" {
		sessionID = "default"
	}
	delete(cb.sessionCalls, sessionID)
	delete(cb.trippedStates, sessionID)
}
