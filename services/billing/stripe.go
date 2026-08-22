package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidSignature = errors.New("invalid stripe webhook signature")
	ErrMalformedPayload = errors.New("malformed stripe webhook payload")
)

// VerifyStripeSignature checks Stripe-Signature header: t=timestamp,v1=signature.
func VerifyStripeSignature(payload []byte, sigHeader string, secret string, tolerance time.Duration) error {
	if sigHeader == "" || secret == "" {
		return ErrInvalidSignature
	}

	var timestampStr string
	var signatures []string

	pairs := strings.Split(sigHeader, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "t":
			timestampStr = parts[1]
		case "v1":
			signatures = append(signatures, parts[1])
		}
	}

	if timestampStr == "" || len(signatures) == 0 {
		return ErrInvalidSignature
	}

	tsInt, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}

	eventTime := time.Unix(tsInt, 0)
	if tolerance > 0 && time.Since(eventTime) > tolerance {
		return fmt.Errorf("%w: timestamp out of tolerance", ErrInvalidSignature)
	}

	// Signed payload: timestamp + "." + raw_payload
	signedData := fmt.Sprintf("%s.%s", timestampStr, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedData))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expectedSig)) {
			return nil
		}
	}

	return ErrInvalidSignature
}

// HandleStripeWebhook processes an incoming Stripe webhook event.
func (s *Service) HandleStripeWebhook(payload []byte, sigHeader string) error {
	if s.webhookSecret != "" {
		if err := VerifyStripeSignature(payload, sigHeader, s.webhookSecret, 5*time.Minute); err != nil {
			return err
		}
	}

	var event StripeWebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return ErrMalformedPayload
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch event.Type {
	case "customer.subscription.created", "customer.subscription.updated":
		return s.processSubscriptionUpdated(event.Data.Object)
	case "customer.subscription.deleted":
		return s.processSubscriptionDeleted(event.Data.Object)
	case "invoice.payment_failed":
		return s.processPaymentFailed(event.Data.Object)
	case "invoice.payment_succeeded":
		return s.processPaymentSucceeded(event.Data.Object)
	}
	return nil
}

func (s *Service) processSubscriptionUpdated(obj map[string]interface{}) error {
	custID, _ := obj["customer"].(string)
	subID, _ := obj["id"].(string)
	statusStr, _ := obj["status"].(string)

	metadata, _ := obj["metadata"].(map[string]interface{})
	orgID, _ := metadata["org_id"].(string)
	tierStr, _ := metadata["tier"].(string)

	if orgID == "" {
		// Attempt to find existing account with this customer ID
		for _, acc := range s.accounts {
			if acc.StripeCustomerID == custID {
				orgID = acc.OrgID
				break
			}
		}
	}
	if orgID == "" {
		return nil
	}

	acc, exists := s.accounts[orgID]
	if !exists {
		acc = &CustomerAccount{
			OrgID:            orgID,
			StripeCustomerID: custID,
		}
		s.accounts[orgID] = acc
	}

	acc.StripeSubscriptionID = subID
	acc.Status = SubscriptionStatus(statusStr)
	if tierStr != "" {
		acc.Tier = PricingTier(tierStr)
	} else if acc.Tier == "" {
		acc.Tier = TierTeam
	}

	if start, ok := obj["current_period_start"].(float64); ok {
		acc.CurrentPeriodStart = time.Unix(int64(start), 0)
	}
	if end, ok := obj["current_period_end"].(float64); ok {
		acc.CurrentPeriodEnd = time.Unix(int64(end), 0)
	}

	return nil
}

func (s *Service) processSubscriptionDeleted(obj map[string]interface{}) error {
	custID, _ := obj["customer"].(string)
	for _, acc := range s.accounts {
		if acc.StripeCustomerID == custID {
			acc.Tier = TierCommunity
			acc.Status = StatusCanceled
			acc.StripeSubscriptionID = ""
			break
		}
	}
	return nil
}

func (s *Service) processPaymentFailed(obj map[string]interface{}) error {
	custID, _ := obj["customer"].(string)
	for _, acc := range s.accounts {
		if acc.StripeCustomerID == custID {
			acc.Status = StatusPastDue
			break
		}
	}
	return nil
}

func (s *Service) processPaymentSucceeded(obj map[string]interface{}) error {
	custID, _ := obj["customer"].(string)
	for _, acc := range s.accounts {
		if acc.StripeCustomerID == custID {
			acc.Status = StatusActive
			break
		}
	}
	return nil
}
