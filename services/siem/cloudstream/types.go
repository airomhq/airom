// Package cloudstream provides high-throughput SIEM event streaming
// to Splunk HEC, Datadog Logs, AWS Security Hub, and Google Chronicle.
package cloudstream

import (
	"time"
)

// DestinationType enumerates supported enterprise SIEM destinations.
type DestinationType string

const (
	DestSplunkHEC       DestinationType = "SPLUNK_HEC"
	DestDatadogLogs     DestinationType = "DATADOG_LOGS"
	DestAWSSecurityHub  DestinationType = "AWS_SECURITY_HUB"
	DestGoogleChronicle DestinationType = "GOOGLE_CHRONICLE"
)

// SIEMSeverity models event risk classification.
type SIEMSeverity string

const (
	SeverityInfo     SIEMSeverity = "INFORMATIONAL"
	SeverityLow      SIEMSeverity = "LOW"
	SeverityMedium   SIEMSeverity = "MEDIUM"
	SeverityHigh     SIEMSeverity = "HIGH"
	SeverityCritical SIEMSeverity = "CRITICAL"
)

// Event models an immutable compliance or security finding exported to SIEM.
type Event struct {
	EventID        string          `json:"eventId"`
	Destination    DestinationType `json:"destination"`
	OrganizationID string          `json:"organizationId"`
	RepositoryID   string          `json:"repositoryId"`
	EventType      string          `json:"eventType"` // e.g. "SHADOW_AI_DETECTED", "COMPLIANCE_GAP", "RED_TEAM_BYPASS"
	Severity       SIEMSeverity    `json:"severity"`
	Title          string          `json:"title"`
	Message        string          `json:"message"`
	HMACSignature  string          `json:"hmacSignature"`
	Timestamp      time.Time       `json:"timestamp"`
	Metadata       map[string]any  `json:"metadata,omitempty"`
}

// DeliveryBatch represents a bundle of events dispatched in one network call.
type DeliveryBatch struct {
	BatchID      string          `json:"batchId"`
	Destination  DestinationType `json:"destination"`
	EventCount   int             `json:"eventCount"`
	Events       []Event         `json:"events"`
	DispatchedAt time.Time       `json:"dispatchedAt"`
}
