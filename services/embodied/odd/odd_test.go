package odd

import (
	"testing"
)

func TestODD_CompliantStackPasses(t *testing.T) {
	evaluator := NewEvaluator()

	spec := ODDSpecification{
		SystemID:            "robotaxi-l4-prod",
		MaxOperationalSpeed: 45.0,
		AllowedWeathers:     []WeatherCondition{WeatherClear, WeatherRain},
		NightOperations:     true,
		SensorRedundancy:    true,
		FallbackManeuver:    FallbackSafeStop,
		HasSOTIFAssessment:  true,
	}

	res := evaluator.EvaluateODD(spec)
	if !res.IsConformant || res.SOTIFScore != 10.0 {
		t.Fatalf("expected conformant system with 10.0 SOTIF score, got: %+v", res)
	}
}

func TestODD_UnguardedStackFails(t *testing.T) {
	evaluator := NewEvaluator()

	unsafeSpec := ODDSpecification{
		SystemID:            "unsafe-high-speed-shuttle",
		MaxOperationalSpeed: 80.0,
		SensorRedundancy:    false, // Single camera only at 80 km/h
		FallbackManeuver:    FallbackNoFailSafe,
		HasSOTIFAssessment:  false,
	}

	res := evaluator.EvaluateODD(unsafeSpec)
	if res.IsConformant || len(res.Violations) < 3 {
		t.Fatalf("expected unsafe system to fail with at least 3 violations, got %d", len(res.Violations))
	}
}
