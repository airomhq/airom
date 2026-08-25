// Package bidirectional implements two-way enterprise ITSM synchronization for Jira and ServiceNow.
package bidirectional

import (
	"time"
)

// Platform identifies the enterprise ITSM system.
type Platform string

const (
	PlatformJira       Platform = "JIRA"
	PlatformServiceNow Platform = "SERVICENOW"
)

// IncidentStatus models the ticket lifecycle state.
type IncidentStatus string

const (
	StatusOpen       IncidentStatus = "OPEN"
	StatusInProgress IncidentStatus = "IN_PROGRESS"
	StatusResolved   IncidentStatus = "RESOLVED"
	StatusAutoClosed IncidentStatus = "AUTO_CLOSED"
)

// Ticket represents a synchronized ITSM incident.
type Ticket struct {
	ID             string         `json:"id"`          // Internal AIROM ticket ID
	ExternalKey    string         `json:"externalKey"` // e.g. "SEC-1042" or "INC0091823"
	Platform       Platform       `json:"platform"`
	RepoID         string         `json:"repoId"`
	ControlID      string         `json:"controlId"` // e.g. "EU-AI-ACT-ART-10"
	Severity       string         `json:"severity"`  // e.g. "HIGH", "CRITICAL"
	Status         IncidentStatus `json:"status"`
	Summary        string         `json:"summary"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	ResolvedAt     *time.Time     `json:"resolvedAt,omitempty"`
	AutoResolution bool           `json:"autoResolution"`
}

// InboundWebhookEvent models a notification received from Jira or ServiceNow.
type InboundWebhookEvent struct {
	EventID     string         `json:"eventId"`
	Platform    Platform       `json:"platform"`
	ExternalKey string         `json:"externalKey"`
	NewStatus   IncidentStatus `json:"newStatus"`
	Timestamp   time.Time      `json:"timestamp"`
}
