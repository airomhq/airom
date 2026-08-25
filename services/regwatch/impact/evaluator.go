package impact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Evaluator evaluates an enterprise inventory against regulatory bill mandates.
type Evaluator struct {
	mu       sync.RWMutex
	mandates []MandateCondition
}

// NewEvaluator constructs an evaluator loaded with standard state AI bill mandates.
func NewEvaluator() *Evaluator {
	e := &Evaluator{}

	// 1. California SB 1047 Frontier Model Mandate
	e.RegisterMandate(MandateCondition{
		MandateID:          "CA-SB1047-FRONTIER",
		StatuteCite:        "Cal. SB 1047 § 22602",
		TargetKind:         airom.KindHostedLLM,
		MinParamCount:      10_000_000_000, // 10B+ params
		RequiresKillSwitch: true,
		RiskLevel:          RiskCritical,
		Description:        "Mandatory full shutdown capability and third-party cybersecurity audit for frontier models.",
	})

	// 2. Massachusetts H.4887 Automated Decision Bias Mandate
	e.RegisterMandate(MandateCondition{
		MandateID:   "MA-H4887-BIAS",
		StatuteCite: "Mass. Gen. Laws ch. 93I § 4",
		TargetKind:  airom.KindHostedLLM,
		RiskLevel:   RiskHigh,
		Description: "Mandatory algorithmic impact assessment for consequential decision-making AI systems.",
	})

	return e
}

// RegisterMandate adds a mandate condition.
func (e *Evaluator) RegisterMandate(m MandateCondition) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mandates = append(e.mandates, m)
}

// EvaluateInventory computes the impact and affected components for a bill.
func (e *Evaluator) EvaluateInventory(billID string, inv *airom.Inventory) *ImpactAssessment {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	if inv == nil {
		return &ImpactAssessment{
			BillID:      billID,
			HighestRisk: RiskInformational,
			EvaluatedAt: now,
		}
	}

	var affected []AffectedComponent
	highestRisk := RiskInformational

	for _, comp := range inv.Components {
		for _, m := range e.mandates {
			if comp.Kind == m.TargetKind {
				// Check parameter threshold if specified
				if m.MinParamCount > 0 && comp.Model != nil {
					if cnt, ok := comp.Model.ParamCount.Value(); ok && cnt < m.MinParamCount {
						continue
					}
				}

				aff := AffectedComponent{
					ComponentID:    comp.ID,
					ComponentName:  comp.Name,
					Kind:           string(comp.Kind),
					MandateID:      m.MandateID,
					StatuteCite:    m.StatuteCite,
					RiskLevel:      m.RiskLevel,
					RequiredAction: m.Description,
				}
				affected = append(affected, aff)

				if isHigherRisk(m.RiskLevel, highestRisk) {
					highestRisk = m.RiskLevel
				}
			}
		}
	}

	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", billID, now.UnixNano())))
	assessmentID := fmt.Sprintf("imp-%s", hex.EncodeToString(h[:6]))

	return &ImpactAssessment{
		AssessmentID:       assessmentID,
		BillID:             billID,
		TotalComponents:    len(inv.Components),
		AffectedCount:      len(affected),
		HighestRisk:        highestRisk,
		AffectedComponents: affected,
		EvaluatedAt:        now,
	}
}

func isHigherRisk(a, b RiskLevel) bool {
	rank := map[RiskLevel]int{
		RiskCritical:      4,
		RiskHigh:          3,
		RiskMedium:        2,
		RiskInformational: 1,
	}
	return rank[a] > rank[b]
}
