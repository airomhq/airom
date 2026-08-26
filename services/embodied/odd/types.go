// Package odd evaluates autonomous mobile robot and vehicle perception pipelines
// against Operational Design Domain (ODD) boundaries, UNECE R155/R156, and ISO 21448 SOTIF norms.
package odd

import (
	"time"
)

// WeatherCondition specifies atmospheric constraints in the ODD.
type WeatherCondition string

const (
	WeatherClear    WeatherCondition = "CLEAR"
	WeatherRain     WeatherCondition = "RAIN"
	WeatherHeavyFog WeatherCondition = "HEAVY_FOG"
	WeatherSnow     WeatherCondition = "SNOW"
)

// FallbackStrategy defines the automated minimum-risk maneuver when AI models operate out-of-domain.
type FallbackStrategy string

const (
	FallbackSafeStop       FallbackStrategy = "IMMEDIATE_CONTROLLED_STOP"
	FallbackLimpHome       FallbackStrategy = "LIMP_HOME_LOW_SPEED"
	FallbackDriverHandover FallbackStrategy = "HUMAN_OPERATOR_HANDOVER"
	FallbackNoFailSafe     FallbackStrategy = "NONE_UNGUARDED"
)

// ODDSpecification defines the authorized operational conditions for an autonomous system.
type ODDSpecification struct {
	SystemID            string             `json:"systemId"`            // e.g. "av-stack-level4"
	MaxOperationalSpeed float64            `json:"maxOperationalSpeed"` // e.g. 50.0 km/h
	AllowedWeathers     []WeatherCondition `json:"allowedWeathers"`     // e.g. [CLEAR, RAIN]
	NightOperations     bool               `json:"nightOperations"`
	SensorRedundancy    bool               `json:"sensorRedundancy"` // Triple redundancy (Camera + LiDAR + Radar)
	FallbackManeuver    FallbackStrategy   `json:"fallbackManeuver"`
	HasSOTIFAssessment  bool               `json:"hasSotifAssessment"` // ISO 21448 SOTIF compliance
}

// ODDConformanceResult contains the safety evaluation verdict for an autonomous system.
type ODDConformanceResult struct {
	SystemID     string    `json:"systemId"`
	IsConformant bool      `json:"isConformant"`
	SOTIFScore   float64   `json:"sotifScore"` // 0.0 to 10.0
	Violations   []string  `json:"violations"`
	EvaluatedAt  time.Time `json:"evaluatedAt"`
}
