// Package webhook delivers real-time legislative alerts and bill progression webhooks
// when state and federal AI regulatory bills advance out of committee or reach floor votes.
package webhook

import (
	"time"
)

// BillStage models the legislative status of a regulatory bill.
type BillStage string

const (
	StageIntroduced      BillStage = "INTRODUCED"
	StageCommitteePassed BillStage = "PASSED_COMMITTEE"
	StageFloorVote       BillStage = "PASSED_FLOOR_VOTE"
	StageEnacted         BillStage = "ENACTED_INTO_LAW"
	StageFailed          BillStage = "FAILED_DIED_IN_COMMITTEE"
)

// BillProgressionEvent represents a live legislative advancement.
type BillProgressionEvent struct {
	BillID           string    `json:"billId"`       // e.g. "MA-H4887", "WA-SB5838", "NY-A09435", "CA-SB1047"
	Jurisdiction     string    `json:"jurisdiction"` // e.g. "Massachusetts", "Washington", "New York", "California"
	BillTitle        string    `json:"billTitle"`
	CurrentStage     BillStage `json:"currentStage"`
	PreviousStage    BillStage `json:"previousStage"`
	EffectiveDateEst string    `json:"effectiveDateEst,omitempty"`
	KeyMandates      []string  `json:"keyMandates"`    // e.g. ["Safety testing for models >10^26 FLOPs", "Kill-switch requirement"]
	ImpactSeverity   string    `json:"impactSeverity"` // "BREAKING_STATUTORY_SHIFT", "OPERATIONAL_DISCLOSURE"
	AdvancedAt       time.Time `json:"advancedAt"`
}

// SubscriberWebhook models an enterprise endpoint receiving real-time alerts.
type SubscriberWebhook struct {
	SubscriberID     string   `json:"subscriberId"`
	TargetURL        string   `json:"targetUrl"`
	SecretKey        string   `json:"secretKey"`
	SubscribedStates []string `json:"subscribedStates"` // e.g. ["California", "ALL"]
}

// OutboundAlertPayload represents the structured payload delivered to customer webhooks.
type OutboundAlertPayload struct {
	AlertID      string               `json:"alertId"`
	Event        BillProgressionEvent `json:"event"`
	Signature    string               `json:"signature"`
	DispatchedAt time.Time            `json:"dispatchedAt"`
}
