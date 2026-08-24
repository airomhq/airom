package transfers

import (
	"fmt"
	"time"
)

// Gate enforces cross-border transfer governance and statutory transfer mechanisms.
type Gate struct{}

// NewGate constructs a cross-border AI transfer gate.
func NewGate() *Gate {
	return &Gate{}
}

// EvaluateTransfer evaluates cross-border movement compliance.
func (g *Gate) EvaluateTransfer(req TransferRequest) TransferDecision {
	// 1. Sanctions Check
	if req.Destination == JurisdictionSanctioned || req.Origin == JurisdictionSanctioned {
		return TransferDecision{
			TransferID:     req.TransferID,
			Approved:       false,
			StatutoryBasis: "OFAC & EU Sanctions Embargo Enforcement",
			MandatoryActions: []string{
				"Block all data and model weight transfers immediately",
				"Log compliance violation to security SIEM",
			},
			EvaluatedAt: time.Now().UTC(),
		}
	}

	// 2. Intra-jurisdiction transfers (e.g. EU -> EU)
	if req.Origin == req.Destination {
		return TransferDecision{
			TransferID:     req.TransferID,
			Approved:       true,
			StatutoryBasis: "Intra-jurisdiction transfer",
			EvaluatedAt:    time.Now().UTC(),
		}
	}

	// 3. EU Outbound Transfers
	if req.Origin == JurisdictionEU_EEA {
		if req.Destination == JurisdictionUK || req.Destination == JurisdictionJapan {
			return TransferDecision{
				TransferID:     req.TransferID,
				Approved:       true,
				StatutoryBasis: "EU Commission Adequacy Decision (GDPR Article 45)",
				EvaluatedAt:    time.Now().UTC(),
			}
		}

		if req.Destination == JurisdictionUS {
			if req.MechanismClaimed == MechanismEU_US_DPF || req.MechanismClaimed == MechanismStandardClauses {
				return TransferDecision{
					TransferID:     req.TransferID,
					Approved:       true,
					StatutoryBasis: fmt.Sprintf("GDPR Chapter V Approved Instrument (%s)", req.MechanismClaimed),
					EvaluatedAt:    time.Now().UTC(),
				}
			}
			return TransferDecision{
				TransferID:     req.TransferID,
				Approved:       false,
				StatutoryBasis: "GDPR Article 44 (Unauthorized Third Country Transfer without Safeguards)",
				MandatoryActions: []string{
					"Execute EU Standard Contractual Clauses (SCCs) Module 1/2",
					"Conduct Transfer Impact Assessment (TIA)",
				},
				EvaluatedAt: time.Now().UTC(),
			}
		}
	}

	// 4. China Outbound Transfers (CAC Regulations)
	if req.Origin == JurisdictionChina {
		if req.MechanismClaimed != MechanismChinaCACApproval {
			return TransferDecision{
				TransferID:     req.TransferID,
				Approved:       false,
				StatutoryBasis: "China CAC Data Export Security Assessment Measures",
				MandatoryActions: []string{
					"File for CAC Security Assessment before cross-border transfer",
					"Execute Standard Contract for Personal Information Export",
				},
				EvaluatedAt: time.Now().UTC(),
			}
		}
	}

	// Default approval for other regular bilateral trade corridors
	return TransferDecision{
		TransferID:     req.TransferID,
		Approved:       true,
		StatutoryBasis: "Standard International Data Exchange Policy",
		EvaluatedAt:    time.Now().UTC(),
	}
}
