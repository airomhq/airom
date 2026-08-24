// Package circuit implements autonomous recursive delegation circuit breakers and goal-drift halters
// for multi-agent systems (ARCHITECTURE.md §16).
package circuit

import (
	"errors"
	"time"
)

// ErrCircuitTripped is returned when an agent invocation is blocked by safety ceilings.
var ErrCircuitTripped = errors.New("circuit breaker: runaway loop or goal drift detected")

// BreakerState defines the current circuit condition.
type BreakerState string

const (
	StateClosed   BreakerState = "CLOSED"    // Normal operation
	StateOpen     BreakerState = "OPEN"      // Tripped / Halting all delegations
	StateHalfOpen BreakerState = "HALF_OPEN" // Cautious test probe
)

// SafetyCeilings specifies hard runtime boundaries for agent swarms.
type SafetyCeilings struct {
	MaxHopDepth       int     `json:"maxHopDepth"`       // Max nested delegation depth (default 8)
	MaxDriftThreshold float64 `json:"maxDriftThreshold"` // Max allowable goal drift (0.0 - 1.0)
	MaxCostCeilingUSD float64 `json:"maxCostCeilingUsd"` // Financial hard stop
	MaxTotalMessages  int     `json:"maxTotalMessages"`  // Message budget before human-in-the-loop review
}

// DefaultSafetyCeilings returns industry-standard safe defaults.
func DefaultSafetyCeilings() SafetyCeilings {
	return SafetyCeilings{
		MaxHopDepth:       8,
		MaxDriftThreshold: 0.85,
		MaxCostCeilingUSD: 50.0,
		MaxTotalMessages:  200,
	}
}

// DelegationCall represents an attempted sub-agent invocation or message transfer.
type DelegationCall struct {
	SessionID  string    `json:"sessionId"`
	CallerID   string    `json:"callerId"`
	CalleeID   string    `json:"calleeId"`
	CurrentHop int       `json:"currentHop"`
	DriftScore float64   `json:"driftScore"`
	CostDelta  float64   `json:"costDelta"`
	Timestamp  time.Time `json:"timestamp"`
}

// HaltReport details the exact condition that tripped the circuit breaker.
type HaltReport struct {
	SessionID       string       `json:"sessionId"`
	State           BreakerState `json:"state"`
	TripReason      string       `json:"tripReason"`
	TotalHops       int          `json:"totalHops"`
	AccumulatedCost float64      `json:"accumulatedCost"`
	TrippedAt       time.Time    `json:"trippedAt"`
}
