package circuit

import (
	"fmt"
	"sync"
	"time"
)

// Breaker enforces safety bounds across multi-agent delegation trees.
type Breaker struct {
	ceilings        SafetyCeilings
	state           BreakerState
	accumulatedCost float64
	totalMessages   int
	tripReason      string
	trippedAt       time.Time
	mu              sync.RWMutex
}

// NewBreaker constructs a multi-agent circuit breaker.
func NewBreaker(ceilings SafetyCeilings) *Breaker {
	return &Breaker{
		ceilings: ceilings,
		state:    StateClosed,
	}
}

// AllowDelegation checks whether a delegation call is permitted or trips the breaker.
func (b *Breaker) AllowDelegation(call DelegationCall) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == StateOpen {
		return fmt.Errorf("%w: circuit currently OPEN (reason: %s)", ErrCircuitTripped, b.tripReason)
	}

	// 1. Check Hop Depth
	if b.ceilings.MaxHopDepth > 0 && call.CurrentHop > b.ceilings.MaxHopDepth {
		b.tripBreaker(fmt.Sprintf("max delegation hop depth exceeded (%d > %d)", call.CurrentHop, b.ceilings.MaxHopDepth))
		return fmt.Errorf("%w: %s", ErrCircuitTripped, b.tripReason)
	}

	// 2. Check Goal Drift
	if b.ceilings.MaxDriftThreshold > 0 && call.DriftScore > b.ceilings.MaxDriftThreshold {
		b.tripBreaker(fmt.Sprintf("critical goal drift detected (score %.2f > %.2f threshold)", call.DriftScore, b.ceilings.MaxDriftThreshold))
		return fmt.Errorf("%w: %s", ErrCircuitTripped, b.tripReason)
	}

	// 3. Check Cost Ceiling
	b.accumulatedCost += call.CostDelta
	if b.ceilings.MaxCostCeilingUSD > 0 && b.accumulatedCost > b.ceilings.MaxCostCeilingUSD {
		b.tripBreaker(fmt.Sprintf("financial cost ceiling exceeded ($%.2f > $%.2f)", b.accumulatedCost, b.ceilings.MaxCostCeilingUSD))
		return fmt.Errorf("%w: %s", ErrCircuitTripped, b.tripReason)
	}

	// 4. Check Total Messages Budget
	b.totalMessages++
	if b.ceilings.MaxTotalMessages > 0 && b.totalMessages > b.ceilings.MaxTotalMessages {
		b.tripBreaker(fmt.Sprintf("total message budget exhausted (%d > %d)", b.totalMessages, b.ceilings.MaxTotalMessages))
		return fmt.Errorf("%w: %s", ErrCircuitTripped, b.tripReason)
	}

	return nil
}

// Reset resets the circuit breaker to closed state after manual intervention.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = StateClosed
	b.tripReason = ""
	b.accumulatedCost = 0.0
	b.totalMessages = 0
}

// Status returns current state and metrics.
func (b *Breaker) Status() HaltReport {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return HaltReport{
		State:           b.state,
		TripReason:      b.tripReason,
		AccumulatedCost: b.accumulatedCost,
		TrippedAt:       b.trippedAt,
	}
}

func (b *Breaker) tripBreaker(reason string) {
	b.state = StateOpen
	b.tripReason = reason
	b.trippedAt = time.Now().UTC()
}
