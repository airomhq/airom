package billing

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// helper to craft signed Stripe-Signature headers for tests
func makeTestStripeSig(payload []byte, secret string, ts time.Time) string {
	tsStr := fmt.Sprintf("%d", ts.Unix())
	signed := fmt.Sprintf("%s.%s", tsStr, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%s,v1=%s", tsStr, sig)
}

// TestQA_AdversarialStripeWebhookAttacks tests fail-closed security for forged signatures,
// replay attacks (>5m tolerance), bit-flipped hashes, secret bruteforce, and malformed JSON.
func TestQA_AdversarialStripeWebhookAttacks(t *testing.T) {
	const validSecret = "whsec_institutional_prod_key_998877"
	svc := NewService(validSecret)
	handler := svc.Routes()

	validPayload := []byte(fmt.Sprintf(`{
		"id": "evt_valid_001",
		"type": "customer.subscription.updated",
		"created": %d,
		"data": {
			"object": {
				"id": "sub_adv_123",
				"customer": "cus_adv_456",
				"status": "active",
				"metadata": {
					"org_id": "org-adv-target",
					"tier": "enterprise"
				}
			}
		}
	}`, time.Now().Unix()))

	t.Run("ForgedSignature_RejectedWith400", func(t *testing.T) {
		forgedHeader := fmt.Sprintf("t=%d,v1=deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef", time.Now().Unix())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook/stripe", bytes.NewReader(validPayload))
		req.Header.Set("Stripe-Signature", forgedHeader)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected HTTP 400 for forged signature, got HTTP %d (%s)", rec.Code, rec.Body.String())
		}

		err := svc.HandleStripeWebhook(validPayload, forgedHeader)
		if err == nil || !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature from HandleStripeWebhook, got: %v", err)
		}
	})

	t.Run("TimestampReplay_OlderThan5Minutes_RejectedWith400", func(t *testing.T) {
		pastTimes := []time.Duration{
			6 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
			24 * time.Hour,
			365 * 24 * time.Hour,
		}

		for _, dt := range pastTimes {
			staleTimestamp := time.Now().Add(-dt)
			staleHeader := makeTestStripeSig(validPayload, validSecret, staleTimestamp)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook/stripe", bytes.NewReader(validPayload))
			req.Header.Set("Stripe-Signature", staleHeader)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 for replayed webhook aged %v, got HTTP %d", dt, rec.Code)
			}

			err := svc.HandleStripeWebhook(validPayload, staleHeader)
			if err == nil {
				t.Fatalf("expected error for replayed webhook aged %v, got nil", dt)
			}
		}
	})

	t.Run("BitFlippedSignature_RejectedWith400", func(t *testing.T) {
		now := time.Now()
		validHeader := makeTestStripeSig(validPayload, validSecret, now)

		// Split header and flip a byte in the signature hash
		parts := makeTestStripeSig(validPayload, validSecret, now)
		sigIdx := len(parts) - 1
		flippedByte := byte('0')
		if parts[sigIdx] == '0' {
			flippedByte = '1'
		}
		bitFlippedHeader := parts[:sigIdx] + string(flippedByte)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook/stripe", bytes.NewReader(validPayload))
		req.Header.Set("Stripe-Signature", bitFlippedHeader)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected HTTP 400 for bit-flipped signature, got HTTP %d", rec.Code)
		}

		err := svc.HandleStripeWebhook(validPayload, bitFlippedHeader)
		if err == nil || !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for bit-flipped signature, got: %v", err)
		}
		_ = validHeader
	})

	t.Run("SecretBruteforce_InvalidCandidates_RejectedWith400", func(t *testing.T) {
		bruteforceCandidates := []string{
			"secret",
			"password",
			"whsec_test",
			"whsec_12345",
			"whsec_admin",
			"stripe_api_key",
			"whsec_institutional_prod_key_998878", // 1 char off
			"",
		}

		for _, candidateSecret := range bruteforceCandidates {
			sigHeader := makeTestStripeSig(validPayload, candidateSecret, time.Now())
			req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook/stripe", bytes.NewReader(validPayload))
			req.Header.Set("Stripe-Signature", sigHeader)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("candidate secret %q succeeded unexpectedly with HTTP %d", candidateSecret, rec.Code)
			}

			err := svc.HandleStripeWebhook(validPayload, sigHeader)
			if err == nil {
				t.Fatalf("candidate secret %q should have been rejected", candidateSecret)
			}
		}
	})

	t.Run("MalformedJSONPayload_RejectedWith400", func(t *testing.T) {
		malformedBodies := [][]byte{
			[]byte(`{"id": "evt_malformed", "type": "customer.subscription.`), // Truncated
			[]byte(`{not_valid_json: 12345}`),                                 // Invalid syntax
			[]byte(``),                                                        // Empty body
			[]byte(`[1, 2, 3, "array_instead_of_object"]`),                    // Array instead of object
			[]byte(`{"id": 12345, "type": ["invalid_type"]}`),                 // Schema type mismatch
		}

		for idx, badBody := range malformedBodies {
			sigHeader := makeTestStripeSig(badBody, validSecret, time.Now())
			req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook/stripe", bytes.NewReader(badBody))
			req.Header.Set("Stripe-Signature", sigHeader)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("malformed payload #%d succeeded with HTTP %d", idx, rec.Code)
			}

			err := svc.HandleStripeWebhook(badBody, sigHeader)
			if err == nil {
				t.Fatalf("malformed payload #%d should have failed parsing in HandleStripeWebhook", idx)
			}
		}
	})

	t.Run("MissingOrMalformedHeaders_RejectedWith400", func(t *testing.T) {
		badHeaders := []string{
			"",
			"invalid_header_format",
			"t=invalid_timestamp,v1=abcdef",
			"v1=abcdef",                            // missing timestamp
			fmt.Sprintf("t=%d", time.Now().Unix()), // missing v1 signature
		}

		for _, header := range badHeaders {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook/stripe", bytes.NewReader(validPayload))
			if header != "" {
				req.Header.Set("Stripe-Signature", header)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("bad signature header %q succeeded with HTTP %d", header, rec.Code)
			}

			err := svc.HandleStripeWebhook(validPayload, header)
			if err == nil {
				t.Fatalf("bad signature header %q should have produced error", header)
			}
		}
	})
}

// TestQA_ConcurrentQuotaStorm_RaceCondition launches 100 concurrent goroutines when an organization
// is at scan count 49/50 (Community limit). Asserts exactly 1 succeeds and 99 are rejected with ErrQuotaExceeded.
func TestQA_ConcurrentQuotaStorm_RaceCondition(t *testing.T) {
	svc := NewService("whsec_race_secret")
	orgID := "org-quota-storm-test"

	// 1. Fill quota to 49/50 (1 remaining scan allowed)
	for i := 0; i < 49; i++ {
		if err := svc.RecordScanUsage(orgID); err != nil {
			t.Fatalf("prerequisite scan %d failed: %v", i+1, err)
		}
	}

	initialUsage := svc.GetUsage(orgID)
	if initialUsage.ScansCount != 49 {
		t.Fatalf("expected initial scan count 49, got %d", initialUsage.ScansCount)
	}

	// 2. Launch 100 concurrent goroutines via synchronization barrier
	const numGoroutines = 100
	var successCount int64
	var quotaExceededCount int64
	var otherErrorCount int64

	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier // wait for synchronized release

			err := svc.RecordScanUsage(orgID)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, ErrQuotaExceeded) {
				atomic.AddInt64(&quotaExceededCount, 1)
			} else {
				atomic.AddInt64(&otherErrorCount, 1)
			}
		}()
	}

	// Release all 100 goroutines simultaneously
	close(startBarrier)
	wg.Wait()

	// 3. Strict atomic assertions
	if successCount != 1 {
		t.Fatalf("CRITICAL RACE CONDITION: expected exactly 1 successful scan, got %d successes", successCount)
	}
	if quotaExceededCount != 99 {
		t.Fatalf("expected 99 requests rejected with ErrQuotaExceeded, got %d", quotaExceededCount)
	}
	if otherErrorCount != 0 {
		t.Fatalf("expected 0 unexpected errors, got %d", otherErrorCount)
	}

	finalUsage := svc.GetUsage(orgID)
	if finalUsage.ScansCount != 50 {
		t.Fatalf("OVERAGE BREACH: expected final scans count to strictly equal 50, got %d", finalUsage.ScansCount)
	}

	// 4. Subsequent scan must also fail cleanly
	postErr := svc.RecordScanUsage(orgID)
	if postErr == nil || !errors.Is(postErr, ErrQuotaExceeded) {
		t.Fatalf("expected post-storm scan to fail with ErrQuotaExceeded, got: %v", postErr)
	}
	if postUsage := svc.GetUsage(orgID); postUsage.ScansCount != 50 {
		t.Fatalf("scans count mutated after rejected scan: got %d, expected 50", postUsage.ScansCount)
	}
}

// TestQA_SubscriptionStateChurn_5KTransitions simulates 5,000 rapid subscription transitions
// (active -> past_due -> canceled -> active) and verifies strict entitlement & quota consistency.
func TestQA_SubscriptionStateChurn_5KTransitions(t *testing.T) {
	secret := "whsec_churn_secret_key"
	svc := NewService(secret)
	orgID := "org-churn-target"
	custID := "cus_churn_999"

	svc.ProvisionAccount(CustomerAccount{
		OrgID:            orgID,
		StripeCustomerID: custID,
		Tier:             TierCommunity,
		Status:           StatusActive,
	})

	const totalTransitions = 5000

	type cycleStep struct {
		name          string
		eventType     string
		status        SubscriptionStatus
		tier          PricingTier
		expectAllowed bool
		expectSIEM    bool
		expectSSO     bool
		maxScans      int
	}

	steps := []cycleStep{
		{
			name:          "Upgrade_Enterprise_Active",
			eventType:     "customer.subscription.updated",
			status:        StatusActive,
			tier:          TierEnterprise,
			expectAllowed: true,
			expectSIEM:    true,
			expectSSO:     true,
			maxScans:      10000,
		},
		{
			name:          "Payment_Failed_PastDue",
			eventType:     "invoice.payment_failed",
			status:        StatusPastDue,
			tier:          TierEnterprise,
			expectAllowed: false,
			expectSIEM:    true, // tier is still enterprise, but status is past_due
			expectSSO:     true,
			maxScans:      10000,
		},
		{
			name:          "Payment_Succeeded_Active",
			eventType:     "invoice.payment_succeeded",
			status:        StatusActive,
			tier:          TierEnterprise,
			expectAllowed: true,
			expectSIEM:    true,
			expectSSO:     true,
			maxScans:      10000,
		},
		{
			name:          "Subscription_Deleted_Canceled",
			eventType:     "customer.subscription.deleted",
			status:        StatusCanceled,
			tier:          TierCommunity,
			expectAllowed: false,
			expectSIEM:    false,
			expectSSO:     false,
			maxScans:      50,
		},
		{
			name:          "Reactivated_Strategic",
			eventType:     "customer.subscription.updated",
			status:        StatusActive,
			tier:          TierStrategic,
			expectAllowed: true,
			expectSIEM:    true,
			expectSSO:     true,
			maxScans:      -1,
		},
		{
			name:          "Downgrade_Team_Active",
			eventType:     "customer.subscription.updated",
			status:        StatusActive,
			tier:          TierTeam,
			expectAllowed: true,
			expectSIEM:    false,
			expectSSO:     false,
			maxScans:      500,
		},
	}

	start := time.Now()

	for i := 0; i < totalTransitions; i++ {
		step := steps[i%len(steps)]

		var payload map[string]interface{}
		switch step.eventType {
		case "customer.subscription.updated":
			payload = map[string]interface{}{
				"id":      fmt.Sprintf("evt_churn_%d", i),
				"type":    step.eventType,
				"created": time.Now().Unix(),
				"data": map[string]interface{}{
					"object": map[string]interface{}{
						"id":                   fmt.Sprintf("sub_churn_%d", i),
						"customer":             custID,
						"status":               string(step.status),
						"current_period_start": float64(time.Now().Unix()),
						"current_period_end":   float64(time.Now().AddDate(0, 1, 0).Unix()),
						"metadata": map[string]interface{}{
							"org_id": orgID,
							"tier":   string(step.tier),
						},
					},
				},
			}
		case "customer.subscription.deleted", "invoice.payment_failed", "invoice.payment_succeeded":
			payload = map[string]interface{}{
				"id":      fmt.Sprintf("evt_churn_%d", i),
				"type":    step.eventType,
				"created": time.Now().Unix(),
				"data": map[string]interface{}{
					"object": map[string]interface{}{
						"customer": custID,
					},
				},
			}
		}

		rawJSON, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("iteration %d: failed to marshal payload: %v", i, err)
		}

		sigHeader := makeTestStripeSig(rawJSON, secret, time.Now())
		if err := svc.HandleStripeWebhook(rawJSON, sigHeader); err != nil {
			t.Fatalf("iteration %d (%s): HandleStripeWebhook failed: %v", i, step.name, err)
		}

		// Verify account state consistency
		acc, ok := svc.GetAccount(orgID)
		if !ok {
			t.Fatalf("iteration %d: account missing", i)
		}
		if acc.Status != step.status {
			t.Fatalf("iteration %d (%s): expected status %s, got %s", i, step.name, step.status, acc.Status)
		}
		if acc.Tier != step.tier {
			t.Fatalf("iteration %d (%s): expected tier %s, got %s", i, step.name, step.tier, acc.Tier)
		}

		// Verify CheckScanAllowed gate
		scanErr := svc.CheckScanAllowed(orgID)
		if step.expectAllowed && scanErr != nil {
			t.Fatalf("iteration %d (%s): expected scan to be allowed, got error: %v", i, step.name, scanErr)
		}
		if !step.expectAllowed && scanErr == nil {
			t.Fatalf("iteration %d (%s): expected scan to be blocked for status %s", i, step.name, step.status)
		}

		// Verify Feature Gates
		siemErr := svc.CheckFeatureAllowed(orgID, "siem_streaming")
		if step.expectSIEM && siemErr != nil {
			t.Fatalf("iteration %d (%s): expected SIEM streaming allowed, got: %v", i, step.name, siemErr)
		}
		if !step.expectSIEM && siemErr == nil {
			t.Fatalf("iteration %d (%s): expected SIEM streaming blocked", i, step.name)
		}

		ssoErr := svc.CheckFeatureAllowed(orgID, "custom_sso")
		if step.expectSSO && ssoErr != nil {
			t.Fatalf("iteration %d (%s): expected SSO allowed, got: %v", i, step.name, ssoErr)
		}
		if !step.expectSSO && ssoErr == nil {
			t.Fatalf("iteration %d (%s): expected SSO blocked", i, step.name)
		}

		// Verify Quotas
		quotas := DefaultQuotas(acc.Tier)
		if quotas.MaxScansPerMonth != step.maxScans {
			t.Fatalf("iteration %d (%s): expected max scans %d, got %d", i, step.name, step.maxScans, quotas.MaxScansPerMonth)
		}
	}

	duration := time.Since(start)
	t.Logf("Successfully executed %d subscription transitions in %v (%.2f ops/sec)",
		totalTransitions, duration, float64(totalTransitions)/duration.Seconds())
}
