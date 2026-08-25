package bidirectional

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Coordinator manages bidirectional ITSM ticket states and automated remediation triggers.
type Coordinator struct {
	mu      sync.RWMutex
	tickets map[string]*Ticket // Key: repoID + ":" + controlID
	byKey   map[string]*Ticket // Key: platform + ":" + externalKey
}

// NewCoordinator constructs a new bidirectional ITSM coordinator.
func NewCoordinator() *Coordinator {
	return &Coordinator{
		tickets: make(map[string]*Ticket),
		byKey:   make(map[string]*Ticket),
	}
}

// OnGapDetected creates or re-opens a ticket when a compliance gap is found.
func (c *Coordinator) OnGapDetected(platform Platform, repoID, controlID, severity, summary string) *Ticket {
	c.mu.Lock()
	defer c.mu.Unlock()

	lookupKey := fmt.Sprintf("%s:%s", repoID, controlID)
	now := time.Now().UTC()

	if t, exists := c.tickets[lookupKey]; exists {
		if t.Status == StatusResolved || t.Status == StatusAutoClosed {
			t.Status = StatusOpen
			t.UpdatedAt = now
			t.ResolvedAt = nil
			t.AutoResolution = false
		}
		return t
	}

	h := sha256.Sum256([]byte(lookupKey + now.Format(time.RFC3339Nano)))
	extKey := fmt.Sprintf("%s-%s", platform, hex.EncodeToString(h[:4]))
	ticket := &Ticket{
		ID:          fmt.Sprintf("tk-%s", hex.EncodeToString(h[:6])),
		ExternalKey: extKey,
		Platform:    platform,
		RepoID:      repoID,
		ControlID:   controlID,
		Severity:    severity,
		Status:      StatusOpen,
		Summary:     summary,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	c.tickets[lookupKey] = ticket
	c.byKey[fmt.Sprintf("%s:%s", platform, extKey)] = ticket
	return ticket
}

// OnGapResolved automatically resolves an open ticket when compliance check passes.
func (c *Coordinator) OnGapResolved(repoID, controlID string) (*Ticket, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	lookupKey := fmt.Sprintf("%s:%s", repoID, controlID)
	t, exists := c.tickets[lookupKey]
	if !exists || t.Status == StatusResolved || t.Status == StatusAutoClosed {
		return nil, false
	}

	now := time.Now().UTC()
	t.Status = StatusAutoClosed
	t.UpdatedAt = now
	t.ResolvedAt = &now
	t.AutoResolution = true
	return t, true
}

// HandleInboundWebhook updates internal state when Jira/ServiceNow status changes.
func (c *Coordinator) HandleInboundWebhook(event InboundWebhookEvent) (*Ticket, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%s:%s", event.Platform, event.ExternalKey)
	t, exists := c.byKey[key]
	if !exists {
		return nil, fmt.Errorf("ticket not found for external key %s", event.ExternalKey)
	}

	t.Status = event.NewStatus
	t.UpdatedAt = event.Timestamp
	if event.NewStatus == StatusResolved {
		t.ResolvedAt = &event.Timestamp
	}
	return t, nil
}

// GetTicket retrieves a ticket by repo and control ID.
func (c *Coordinator) GetTicket(repoID, controlID string) (*Ticket, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, exists := c.tickets[fmt.Sprintf("%s:%s", repoID, controlID)]
	return t, exists
}
