// Package calendar tracks multi-jurisdiction regulatory enforcement deadlines,
// public comment periods, and statutory grace period countdowns.
package calendar

import (
	"time"
)

// MilestoneType classifies the regulatory calendar event.
type MilestoneType string

const (
	TypeStatutoryEnactment MilestoneType = "STATUTORY_ENACTMENT"
	TypeGracePeriodEnd     MilestoneType = "GRACE_PERIOD_END"
	TypeAnnualAuditDue     MilestoneType = "ANNUAL_AUDIT_DUE"
	TypePublicCommentClose MilestoneType = "PUBLIC_COMMENT_CLOSE"
)

// StatutoryMilestone defines a hard legislative enforcement date.
type StatutoryMilestone struct {
	MilestoneID   string        `json:"milestoneId"`
	Jurisdiction  string        `json:"jurisdiction"` // e.g. "Colorado", "EU", "NYC", "California"
	StatuteName   string        `json:"statuteName"`  // e.g. "CO SB 24-205 § 6-1-1703", "EU AI Act Annex IV"
	Type          MilestoneType `json:"type"`
	DeadlineDate  time.Time     `json:"deadlineDate"`
	MandatoryTask string        `json:"mandatoryTask"` // e.g. "Complete initial developer impact assessment"
	Penalties     string        `json:"penalties"`     // e.g. "Up to $20,000 per violation under AG enforcement"
}

// ActionNotice represents a scheduled compliance warning for an upcoming deadline.
type ActionNotice struct {
	MilestoneID   string `json:"milestoneId"`
	Jurisdiction  string `json:"jurisdiction"`
	StatuteName   string `json:"statuteName"`
	DaysRemaining int    `json:"daysRemaining"`
	IsOverdue     bool   `json:"isOverdue"`
	Urgency       string `json:"urgency"` // "URGENT_ACTION_REQUIRED", "UPCOMING_DEADLINE", "MONITORING"
	Task          string `json:"task"`
}
