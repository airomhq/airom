package treaty

import (
	"fmt"
	"sync"
	"time"
)

// Evaluator checks frontier model commitments against international treaty accords.
type Evaluator struct {
	mu sync.RWMutex
}

// NewEvaluator constructs a new global treaty evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// EvaluateModel evaluates a model against an international safety accord.
func (e *Evaluator) EvaluateModel(framework TreatyFramework, spec FrontierSafetyCommitments) TreatyEvaluationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	const frontierFLOPThreshold = 1e26

	// Frontier model compute check
	if spec.EstimatedFLOPs >= frontierFLOPThreshold {
		if !spec.HasIndependentRedTeam {
			violations = append(violations, fmt.Sprintf("CRITICAL: Frontier model (%.1e FLOPs) lacks external independent third-party red-teaming (%s)", spec.EstimatedFLOPs, framework))
		}

		if !spec.HasCBRNEvaluation {
			violations = append(violations, "CRITICAL: Model lacks formal CBRN (Chemical, Biological, Radiological, Nuclear) dual-use safety evaluation")
		}

		if !spec.HasCyberOffenseLimits {
			violations = append(violations, "HIGH: Model lacks autonomous cyber-offensive capability containment safeguards")
		}

		if !spec.ResponsibleScalingPolicy {
			violations = append(violations, "HIGH: Frontier developer has not published a binding Responsible Scaling Policy (RSP)")
		}
	}

	if !spec.HasEmergencyKillSwitch {
		violations = append(violations, "HIGH: Model lacks mandatory hardware/software emergency kill-switch capability")
	}

	return TreatyEvaluationResult{
		ModelName:    spec.ModelName,
		Framework:    framework,
		IsConformant: len(violations) == 0,
		Violations:   violations,
		EvaluatedAt:  now,
	}
}
