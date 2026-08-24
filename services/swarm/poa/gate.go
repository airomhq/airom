package poa

import (
	"fmt"
	"sync"
	"time"
)

// Gate evaluates agent action requests against enterprise POA grants.
type Gate struct {
	grants map[string]POAGrant
	mu     sync.RWMutex
}

// NewGate constructs a POA bounds gate.
func NewGate() *Gate {
	return &Gate{
		grants: make(map[string]POAGrant),
	}
}

// RegisterGrant stores an agent's delegated authority limits.
func (g *Gate) RegisterGrant(grant POAGrant) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants[grant.AgentID] = grant
}

// EvaluateAction decides if an agent's transaction is authorized.
func (g *Gate) EvaluateAction(req ActionRequest) POADecision {
	g.mu.RLock()
	defer g.mu.RUnlock()

	grant, ok := g.grants[req.AgentID]
	if !ok {
		return POADecision{
			RequestID:   req.RequestID,
			Approved:    false,
			Reason:      fmt.Sprintf("no active POA grant found for agent: %s", req.AgentID),
			EvaluatedAt: time.Now().UTC(),
		}
	}

	// 1. Check Expiration
	if !grant.ValidUntil.IsZero() && time.Now().UTC().After(grant.ValidUntil) {
		return POADecision{
			RequestID:   req.RequestID,
			Approved:    false,
			Reason:      "POA grant expired",
			EvaluatedAt: time.Now().UTC(),
		}
	}

	// 2. Check Scope Authorization
	hasScope := false
	for _, s := range grant.AuthorizedScopes {
		if s == req.Scope {
			hasScope = true
			break
		}
	}
	if !hasScope {
		return POADecision{
			RequestID:   req.RequestID,
			Approved:    false,
			Reason:      fmt.Sprintf("agent lacks authorized scope: %s", req.Scope),
			EvaluatedAt: time.Now().UTC(),
		}
	}

	// 3. Check Financial Ceilings (for financial payments)
	if req.Scope == ScopeFinancialPayment {
		if req.AmountUSD < 0 {
			return POADecision{
				RequestID:   req.RequestID,
				Approved:    false,
				Reason:      "negative transaction amounts forbidden",
				EvaluatedAt: time.Now().UTC(),
			}
		}

		if grant.PerTransactionMaxUSD > 0 && req.AmountUSD > grant.PerTransactionMaxUSD {
			return POADecision{
				RequestID:   req.RequestID,
				Approved:    false,
				Reason:      fmt.Sprintf("transaction amount $%.2f exceeds per-transaction limit $%.2f", req.AmountUSD, grant.PerTransactionMaxUSD),
				EvaluatedAt: time.Now().UTC(),
			}
		}

		// Check Dual Custody Requirement
		if grant.DualCustodyThreshold > 0 && req.AmountUSD >= grant.DualCustodyThreshold {
			if req.HumanCoSigner == "" {
				return POADecision{
					RequestID:        req.RequestID,
					Approved:         false,
					RequiresCoSigner: true,
					Reason:           fmt.Sprintf("transaction amount $%.2f exceeds dual custody threshold $%.2f (human co-signer required)", req.AmountUSD, grant.DualCustodyThreshold),
					EvaluatedAt:      time.Now().UTC(),
				}
			}
		}
	}

	return POADecision{
		RequestID:   req.RequestID,
		Approved:    true,
		Reason:      "authorized within POA bounds",
		EvaluatedAt: time.Now().UTC(),
	}
}
