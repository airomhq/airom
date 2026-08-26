package odd

import (
	"testing"
)

func TestQA_AdversarialNegativeSpeedLimit(t *testing.T) {
	evaluator := NewEvaluator()

	negSpec := ODDSpecification{
		SystemID:            "neg_speed",
		MaxOperationalSpeed: -100.0,
		FallbackManeuver:    FallbackSafeStop,
	}

	res := evaluator.EvaluateODD(negSpec)
	// Missing SOTIF should trigger violation
	if res.IsConformant {
		t.Fatalf("expected negative speed spec without SOTIF to trigger violation")
	}
}

func TestQA_AdversarialContradictoryWeatherPermutations(t *testing.T) {
	evaluator := NewEvaluator()

	spec := ODDSpecification{
		SystemID:            "weather_conflict",
		MaxOperationalSpeed: 30.0,
		AllowedWeathers:     []WeatherCondition{WeatherHeavyFog, WeatherHeavyFog, WeatherHeavyFog},
		SensorRedundancy:    false, // Fog without redundancy
		FallbackManeuver:    FallbackSafeStop,
		HasSOTIFAssessment:  true,
	}

	res := evaluator.EvaluateODD(spec)
	if res.IsConformant {
		t.Fatalf("expected heavy fog without redundancy to fail conformance")
	}
}
