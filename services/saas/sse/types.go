// Package sse implements high-concurrency Server-Sent Events (SSE) real-time event broadcasting
// for the hosted SaaS cockpit and web dashboard.
package sse

import (
	"time"
)

// EventType categorizes real-time push events.
type EventType string

const (
	EventScanStarted     EventType = "SCAN_STARTED"
	EventScanCompleted   EventType = "SCAN_COMPLETED"
	EventAnomalyDetected EventType = "ANOMALY_DETECTED"
	EventFilingSubmitted EventType = "FILING_SUBMITTED"
	EventRedTeamAlert    EventType = "RED_TEAM_ALERT"
)

// Message models a structured event payload delivered to connected SSE clients.
type Message struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Type      EventType `json:"type"`
	Payload   string    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// Client represents a connected browser or terminal SSE stream listener.
type Client struct {
	ID      string
	OrgID   string
	Channel chan Message
}
