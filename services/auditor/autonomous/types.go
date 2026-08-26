// Package autonomous provides continuous zero-touch compliance auditing
// reacting dynamically to live statutory alerts and automated model changes.
package autonomous

import (
	"time"
)

// TriggerType specifies what initiated the autonomous audit run.
type TriggerType string

const (
	TriggerRegWatchBill  TriggerType = "REGWATCH_BILL_ADVANCED"
	TriggerModelVersion  TriggerType = "MODEL_VERSION_CHANGE"
	TriggerContinuousJob TriggerType = "SCHEDULED_CONTINUOUS"
)

// AuditEvent models an incoming statutory or code update trigger.
type AuditEvent struct {
	EventID      string      `json:"eventId"`
	Type         TriggerType `json:"type"`
	Organization string      `json:"organization"`
	Repository   string      `json:"repository"`
	BillID       string      `json:"billId,omitempty"`
	TriggeredAt  time.Time   `json:"triggeredAt"`
}

// AuditRunResult contains the autonomous audit findings and triggered remediations.
type AuditRunResult struct {
	RunID          string      `json:"runId"`
	Repository     string      `json:"repository"`
	TriggerType    TriggerType `json:"triggerType"`
	GapsIdentified int         `json:"gapsIdentified"`
	TicketsCreated int         `json:"ticketsCreated"`
	CompletedAt    time.Time   `json:"completedAt"`
}
