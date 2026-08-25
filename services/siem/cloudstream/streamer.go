package cloudstream

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Streamer coordinates high-throughput batching and cryptographic signing of enterprise SIEM feeds.
type Streamer struct {
	mu        sync.RWMutex
	secretKey []byte
	buffers   map[DestinationType][]Event
	batchSize int
}

// NewStreamer constructs a new cloud SIEM streamer.
func NewStreamer(secretKey []byte, batchSize int) *Streamer {
	if len(secretKey) == 0 {
		secretKey = []byte("airom-enterprise-siem-default-secret-key")
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	return &Streamer{
		secretKey: secretKey,
		buffers:   make(map[DestinationType][]Event),
		batchSize: batchSize,
	}
}

// IngestEvent signs and appends an event to the destination buffer.
func (s *Streamer) IngestEvent(dest DestinationType, orgID, repoID, eventType string, sev SIEMSeverity, title, msg string) *Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	rawID := fmt.Sprintf("%s-%s-%s-%d", orgID, repoID, eventType, now.UnixNano())
	h := sha256.Sum256([]byte(rawID))
	eventID := fmt.Sprintf("evt-%s", hex.EncodeToString(h[:6]))

	sigPayload := fmt.Sprintf("%s|%s|%s|%s|%s|%s", eventID, string(dest), orgID, repoID, eventType, now.Format(time.RFC3339Nano))
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(sigPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	event := Event{
		EventID:        eventID,
		Destination:    dest,
		OrganizationID: orgID,
		RepositoryID:   repoID,
		EventType:      eventType,
		Severity:       sev,
		Title:          title,
		Message:        msg,
		HMACSignature:  sig,
		Timestamp:      now,
	}

	s.buffers[dest] = append(s.buffers[dest], event)
	return &event
}

// FlushDestination extracts and returns all queued events for a destination as a DeliveryBatch.
func (s *Streamer) FlushDestination(dest DestinationType) *DeliveryBatch {
	s.mu.Lock()
	defer s.mu.Unlock()

	events := s.buffers[dest]
	if len(events) == 0 {
		return nil
	}

	now := time.Now().UTC()
	h := sha256.Sum256([]byte(string(dest) + now.Format(time.RFC3339Nano)))
	batchID := fmt.Sprintf("batch-%s", hex.EncodeToString(h[:6]))

	batch := &DeliveryBatch{
		BatchID:      batchID,
		Destination:  dest,
		EventCount:   len(events),
		Events:       events,
		DispatchedAt: now,
	}

	// Reset buffer
	s.buffers[dest] = nil
	return batch
}

// VerifyEventSignature validates the cryptographic HMAC signature of an ingested SIEM event.
func (s *Streamer) VerifyEventSignature(event Event) bool {
	sigPayload := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		event.EventID, string(event.Destination), event.OrganizationID, event.RepositoryID, event.EventType, event.Timestamp.Format(time.RFC3339Nano))
	mac := hmac.New(sha256.New, s.secretKey)
	mac.Write([]byte(sigPayload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(event.HMACSignature), []byte(expected))
}
