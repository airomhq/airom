package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Standard errors returned by the SIEM event streamer.
var (
	// ErrDestinationDisabled indicates that the SIEM destination is currently disabled.
	ErrDestinationDisabled = errors.New("siem destination is disabled")
	// ErrInvalidConfig indicates the SIEM destination configuration is invalid.
	ErrInvalidConfig = errors.New("invalid siem configuration")
	// ErrDeliveryFailed indicates delivery to the SIEM destination failed after retries.
	ErrDeliveryFailed = errors.New("siem event delivery failed")
)

// HTTPClient interface allows mocking HTTP requests in tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Service manages SOC 2 audit events and real-time SIEM streaming.
type Service struct {
	mu           sync.RWMutex
	signingKey   string
	events       []AuditEvent
	configs      map[string]SIEMConfig // orgID -> SIEMConfig
	client       HTTPClient
	eventChannel chan AuditEvent
	stopCh       chan struct{}
}

// NewService creates a new SOC 2 Audit & SIEM Streaming service.
func NewService(signingKey string, client HTTPClient) *Service {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	s := &Service{
		signingKey:   signingKey,
		events:       make([]AuditEvent, 0),
		configs:      make(map[string]SIEMConfig),
		client:       client,
		eventChannel: make(chan AuditEvent, 10000),
		stopCh:       make(chan struct{}),
	}
	go s.eventWorker()
	return s
}

// Close gracefully stops background stream workers.
func (s *Service) Close() {
	close(s.stopCh)
}

// RecordEvent records and signs an immutable SOC 2 audit event, and pushes it to the SIEM stream.
func (s *Service) RecordEvent(ctx context.Context, e AuditEvent) (*AuditEvent, error) {
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d-%s", time.Now().UTC().UnixNano(), e.OrgID)
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = SeverityInfo
	}
	if e.SOC2Control == "" {
		e.SOC2Control = SOC2_CC6_6
	}

	// Sign the event
	e.Signature = e.ComputeSignature(s.signingKey)

	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()

	// Non-blocking push to streaming worker
	select {
	case s.eventChannel <- e:
	default:
		// Buffer full: in high load, do not block caller
	}

	return &e, nil
}

// GetEvents returns all audit events for a given org.
func (s *Service) GetEvents(orgID string) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []AuditEvent
	for _, e := range s.events {
		if e.OrgID == orgID {
			out = append(out, e)
		}
	}
	return out
}

// ConfigureSIEM sets or updates external SIEM streaming destination for an organization.
func (s *Service) ConfigureSIEM(cfg SIEMConfig) error {
	if cfg.OrgID == "" || cfg.EndpointURL == "" {
		return ErrInvalidConfig
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[cfg.OrgID] = cfg
	return nil
}

// GetSIEMConfig retrieves SIEM configuration for an organization.
func (s *Service) GetSIEMConfig(orgID string) (SIEMConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.configs[orgID]
	return cfg, ok
}

// StreamEvent directly delivers an event to its destination (synchronous dispatch with retries).
func (s *Service) StreamEvent(ctx context.Context, e *AuditEvent) error {
	s.mu.RLock()
	cfg, exists := s.configs[e.OrgID]
	s.mu.RUnlock()

	if !exists || !cfg.Enabled {
		return ErrDestinationDisabled
	}

	var payload []byte
	var err error

	switch cfg.Destination {
	case SIEMDatadog:
		payload, err = FormatForDatadog(e)
	case SIEMSplunk:
		payload, err = FormatForSplunk(e)
	default:
		payload, err = FormatForWebhook(e)
	}
	if err != nil {
		return fmt.Errorf("format payload error: %w", err)
	}

	return s.deliverWithRetry(ctx, cfg, payload)
}

func (s *Service) deliverWithRetry(ctx context.Context, cfg SIEMConfig, payload []byte) error {
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	var lastErr error
	backoff := 50 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EndpointURL, bytes.NewReader(payload))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AIROM-AuditStreamer/1.0")

		switch cfg.Destination {
		case SIEMDatadog:
			req.Header.Set("DD-API-KEY", cfg.APIKey)
		case SIEMSplunk:
			req.Header.Set("Authorization", "Splunk "+cfg.APIKey)
		case SIEMWebhook:
			if cfg.SecretKey != "" {
				mac := hmac.New(sha256.New, []byte(cfg.SecretKey))
				mac.Write(payload)
				sig := hex.EncodeToString(mac.Sum(nil))
				req.Header.Set("X-AIROM-Signature", "sha256="+sig)
			}
		}

		resp, err := s.client.Do(req)
		if err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				_ = resp.Body.Close()
				return nil
			}
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		} else {
			lastErr = err
		}

		time.Sleep(backoff)
		backoff *= 2
	}

	return fmt.Errorf("%w: %v", ErrDeliveryFailed, lastErr)
}

func (s *Service) eventWorker() {
	for {
		select {
		case <-s.stopCh:
			return
		case evt := <-s.eventChannel:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = s.StreamEvent(ctx, &evt)
			cancel()
		}
	}
}
