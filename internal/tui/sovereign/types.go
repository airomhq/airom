// Package sovereign implements the interactive sovereign enterprise terminal TUI (ARCHITECTURE.md §16).
package sovereign

import (
	"time"
)

// ViewMode selects the active screen displayed in the sovereign terminal.
type ViewMode string

const (
	ViewDashboard   ViewMode = "DASHBOARD"
	ViewThreatRadar ViewMode = "THREAT_RADAR"
	ViewDriftOracle ViewMode = "DRIFT_ORACLE"
	ViewFilings     ViewMode = "STATUTORY_FILINGS"
)

// TerminalState captures the live interactive state of the sovereign TUI.
type TerminalState struct {
	ActiveView      ViewMode  `json:"activeView"`
	SystemName      string    `json:"systemName"`
	ComplianceScore float64   `json:"complianceScore"`
	ActiveAlerts    int       `json:"activeAlerts"`
	ActiveThreats   int       `json:"activeThreats"`
	DriftStatus     string    `json:"driftStatus"`
	RenderedAt      time.Time `json:"renderedAt"`
}
