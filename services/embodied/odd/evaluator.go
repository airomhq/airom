package odd

import (
	"fmt"
	"sync"
	"time"
)

// Evaluator checks autonomous vehicle and robotics stacks against SOTIF and ODD standards.
type Evaluator struct {
	mu sync.RWMutex
}

// NewEvaluator constructs a new ODD safety evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// EvaluateODD verifies whether an autonomous system specification satisfies ISO 21448 / UNECE R155.
func (e *Evaluator) EvaluateODD(spec ODDSpecification) ODDConformanceResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string
	score := 10.0

	// 1. Mandatory Minimum Risk Maneuver (MRM) Fail-Safe
	if spec.FallbackManeuver == FallbackNoFailSafe || spec.FallbackManeuver == "" {
		violations = append(violations, "CRITICAL: System lacks automated Minimum Risk Maneuver (MRM) fallback policy (violates UNECE R155)")
		score -= 4.0
	}

	// 2. Sensor Redundancy for High Speed (>25 km/h)
	if spec.MaxOperationalSpeed > 25.0 && !spec.SensorRedundancy {
		violations = append(violations, fmt.Sprintf("HIGH: Speed envelope (%.1f km/h) requires multi-modal sensor redundancy (Camera + LiDAR/Radar) under ISO 21448", spec.MaxOperationalSpeed))
		score -= 3.0
	}

	// 3. SOTIF Formal Assessment
	if !spec.HasSOTIFAssessment {
		violations = append(violations, "HIGH: ISO 21448 SOTIF (Safety of the Intended Functionality) risk analysis not completed")
		score -= 2.0
	}

	// 4. Heavy Weather Boundaries
	for _, w := range spec.AllowedWeathers {
		if w == WeatherHeavyFog && !spec.SensorRedundancy {
			violations = append(violations, "HIGH: Heavy fog operations authorized without active Radar/LiDAR penetration redundancy")
			score -= 2.0
			break
		}
	}

	if score < 0.0 {
		score = 0.0
	}

	return ODDConformanceResult{
		SystemID:     spec.SystemID,
		IsConformant: len(violations) == 0,
		SOTIFScore:   score,
		Violations:   violations,
		EvaluatedAt:  now,
	}
}
