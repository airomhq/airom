// Package incidents implements automated serious AI incident reporting and statutory regulatory dispatch
// pursuant to EU AI Act Article 73 and Colorado AI Act § 6-1-1703 (ARCHITECTURE.md §16).
package incidents

import (
	"time"
)

// IncidentSeverity classifies the statutory severity of an AI incident.
type IncidentSeverity string

const (
	SeverityDeathOrPhysicalHarm  IncidentSeverity = "DEATH_OR_SEVERE_HEALTH_HARM"              // 72-hour mandatory deadline (Art 73(2))
	SeverityCriticalInfraDisrupt IncidentSeverity = "CRITICAL_INFRASTRUCTURE_DISRUPT"          // 15-day mandatory deadline (Art 73(3))
	SeverityFundamentalRights    IncidentSeverity = "SERIOUS_FUNDAMENTAL_RIGHTS_BREACH"        // 15-day mandatory deadline
	SeverityAlgorithmicBias      IncidentSeverity = "CONSEQUENTIAL_ALGORITHMIC_DISCRIMINATION" // 90-day CO AG notice (§ 6-1-1703)
)

// AIIncidentInput describes an adverse production event involving an AI system.
type AIIncidentInput struct {
	IncidentID          string           `json:"incidentId"`
	SystemName          string           `json:"systemName"`
	Provider            string           `json:"provider"`
	Severity            IncidentSeverity `json:"severity"`
	AffectedIndividuals int              `json:"affectedIndividuals"`
	HarmDescription     string           `json:"harmDescription"`
	OccurredAt          time.Time        `json:"occurredAt"`
}

// StatutoryDispatchPackage contains formatted notices for regulatory authorities.
type StatutoryDispatchPackage struct {
	IncidentID          string           `json:"incidentId"`
	Severity            IncidentSeverity `json:"severity"`
	MandatoryDeadline   time.Time        `json:"mandatoryDeadline"`
	NotificationWindow  string           `json:"notificationWindow"` // "72_HOURS" | "15_DAYS" | "90_DAYS"
	TargetAuthorities   []string         `json:"targetAuthorities"`  // EU Market Surveillance Authority, Colorado AG, FTC
	StatutoryDirectives []string         `json:"statutoryDirectives"`
	TriagedAt           time.Time        `json:"triagedAt"`
}
