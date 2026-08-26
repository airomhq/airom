// Package cockpit provides an embedded, zero-dependency interactive enterprise web UI
// for real-time AIBOM discovery, live SSE statutory feeds, and executive compliance scorecards.
package cockpit

import (
	"time"
)

// CockpitConfig models configuration for the embedded cockpit server.
type CockpitConfig struct {
	Port         int    `json:"port"`         // Default 8088
	Organization string `json:"organization"` // Default "Enterprise AI"
	EnableSSE    bool   `json:"enableSSE"`
}

// CockpitState captures real-time enterprise AI posture.
type CockpitState struct {
	Organization     string    `json:"organization"`
	TotalComponents  int       `json:"totalComponents"`
	TotalGaps        int       `json:"totalGaps"`
	TotalMetControls int       `json:"totalMetControls"`
	ActiveModels     []string  `json:"activeModels"`
	SyncStatus       string    `json:"syncStatus"` // "SYNCHRONIZED"
	UpdatedAt        time.Time `json:"updatedAt"`
}

// CockpitEvent represents a live SSE push alert.
type CockpitEvent struct {
	EventID   string    `json:"eventId"`
	Type      string    `json:"type"` // "REGWATCH_ALERT", "GAP_DETECTED"
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}
