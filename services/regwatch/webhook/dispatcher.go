package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Dispatcher coordinates subscriber registrations and outbound legislative webhook delivery.
type Dispatcher struct {
	mu          sync.RWMutex
	subscribers map[string]*SubscriberWebhook
}

// NewDispatcher constructs a new legislative webhook dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		subscribers: make(map[string]*SubscriberWebhook),
	}
}

// RegisterSubscriber registers an enterprise webhook destination.
func (d *Dispatcher) RegisterSubscriber(sub SubscriberWebhook) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subscribers[sub.SubscriberID] = &sub
}

// DispatchBillEvent evaluates subscribers and constructs signed outbound payloads for eligible listeners.
func (d *Dispatcher) DispatchBillEvent(event BillProgressionEvent) []OutboundAlertPayload {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().UTC()
	var deliveries []OutboundAlertPayload

	for _, sub := range d.subscribers {
		if !isSubscribed(sub.SubscribedStates, event.Jurisdiction) {
			continue
		}

		rawID := fmt.Sprintf("%s-%s-%d", sub.SubscriberID, event.BillID, now.UnixNano())
		h := sha256.Sum256([]byte(rawID))
		alertID := fmt.Sprintf("alt-%s", hex.EncodeToString(h[:6]))

		sigPayload := fmt.Sprintf("%s|%s|%s|%s", alertID, event.BillID, string(event.CurrentStage), now.Format(time.RFC3339Nano))
		mac := hmac.New(sha256.New, []byte(sub.SecretKey))
		mac.Write([]byte(sigPayload))
		sig := hex.EncodeToString(mac.Sum(nil))

		deliveries = append(deliveries, OutboundAlertPayload{
			AlertID:      alertID,
			Event:        event,
			Signature:    sig,
			DispatchedAt: now,
		})
	}

	return deliveries
}

func isSubscribed(filters []string, jurisdiction string) bool {
	for _, f := range filters {
		if strings.EqualFold(f, "ALL") || strings.EqualFold(f, jurisdiction) {
			return true
		}
	}
	return false
}
