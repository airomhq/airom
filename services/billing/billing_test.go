package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateStripeSignature(payload []byte, secret string, ts time.Time) string {
	tsStr := fmt.Sprintf("%d", ts.Unix())
	signed := fmt.Sprintf("%s.%s", tsStr, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%s,v1=%s", tsStr, sig)
}

func TestQuota_DefaultCommunityLimitsAndOverage(t *testing.T) {
	svc := NewService("stripe-webhook-secret")
	orgID := "org-free-tier"

	// 1. Initial Community state (50 scans allowed)
	for i := 0; i < 50; i++ {
		if err := svc.RecordScanUsage(orgID); err != nil {
			t.Fatalf("scan %d failed unexpectedly: %v", i+1, err)
		}
	}

	// 2. 51st scan must be rejected with ErrQuotaExceeded
	err := svc.RecordScanUsage(orgID)
	if err == nil {
		t.Fatalf("expected 51st scan to fail due to quota limit")
	}
	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("expected quota exceeded error, got: %v", err)
	}

	// 3. Feature Gate check: Community cannot use SIEM streaming
	if err := svc.CheckFeatureAllowed(orgID, "siem_streaming"); err == nil {
		t.Errorf("expected feature gate to block siem streaming on community tier")
	}
}

func TestStripe_WebhookSubscriptionLifecycle(t *testing.T) {
	secret := "whsec_test_secret_12345"
	svc := NewService(secret)
	orgID := "org-enterprise-corp"

	// 1. Send subscription.created webhook upgrading to Enterprise
	subCreatedPayload := fmt.Sprintf(`{
		"id": "evt_sub_001",
		"type": "customer.subscription.created",
		"created": %d,
		"data": {
			"object": {
				"id": "sub_stripe_999",
				"customer": "cus_stripe_111",
				"status": "active",
				"current_period_start": %d,
				"current_period_end": %d,
				"metadata": {
					"org_id": "%s",
					"tier": "enterprise"
				}
			}
		}
	}`, time.Now().Unix(), time.Now().Unix(), time.Now().AddDate(1, 0, 0).Unix(), orgID)

	sigHeader := generateStripeSignature([]byte(subCreatedPayload), secret, time.Now())
	err := svc.HandleStripeWebhook([]byte(subCreatedPayload), sigHeader)
	if err != nil {
		t.Fatalf("failed to process subscription created webhook: %v", err)
	}

	// 2. Verify account upgraded to Enterprise
	acc, ok := svc.GetAccount(orgID)
	if !ok || acc.Tier != TierEnterprise || acc.Status != StatusActive {
		t.Fatalf("expected active enterprise account, got: %+v", acc)
	}

	// 3. Enterprise tier allows SIEM streaming and custom SSO
	if err := svc.CheckFeatureAllowed(orgID, "siem_streaming"); err != nil {
		t.Errorf("enterprise should allow siem streaming: %v", err)
	}
	if err := svc.CheckFeatureAllowed(orgID, "custom_sso"); err != nil {
		t.Errorf("enterprise should allow custom sso: %v", err)
	}

	// 4. Test invoice.payment_failed -> transitions to past_due
	payFailedPayload := `{
		"id": "evt_inv_002",
		"type": "invoice.payment_failed",
		"data": {
			"object": {
				"customer": "cus_stripe_111"
			}
		}
	}`
	sigHeader2 := generateStripeSignature([]byte(payFailedPayload), secret, time.Now())
	_ = svc.HandleStripeWebhook([]byte(payFailedPayload), sigHeader2)

	acc, _ = svc.GetAccount(orgID)
	if acc.Status != StatusPastDue {
		t.Errorf("expected status past_due, got: %s", acc.Status)
	}

	// 5. Past due account cannot execute scans
	if err := svc.CheckScanAllowed(orgID); err == nil {
		t.Errorf("expected past_due account to be blocked from scanning")
	}

	// 6. Test invoice.payment_succeeded -> recovers to active
	paySuccessPayload := `{
		"id": "evt_inv_003",
		"type": "invoice.payment_succeeded",
		"data": {
			"object": {
				"customer": "cus_stripe_111"
			}
		}
	}`
	sigHeader3 := generateStripeSignature([]byte(paySuccessPayload), secret, time.Now())
	_ = svc.HandleStripeWebhook([]byte(paySuccessPayload), sigHeader3)

	acc, _ = svc.GetAccount(orgID)
	if acc.Status != StatusActive {
		t.Errorf("expected status active after successful payment, got: %s", acc.Status)
	}
}

func TestBilling_REST_API_Endpoints(t *testing.T) {
	secret := "whsec_rest_test"
	svc := NewService(secret)
	orgID := "org-rest-client"

	svc.ProvisionAccount(CustomerAccount{
		OrgID:            orgID,
		StripeCustomerID: "cus_rest_777",
		Tier:             TierTeam,
		Status:           StatusActive,
	})

	server := httptest.NewServer(svc.Routes())
	defer server.Close()

	// 1. GET /api/v1/billing/subscription
	resp, err := http.Get(server.URL + "/api/v1/billing/subscription?org_id=" + orgID)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to get subscription: resp=%+v, err=%v", resp, err)
	}
	var subRes struct {
		Account CustomerAccount `json:"account"`
		Quotas  TierQuotas      `json:"quotas"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&subRes)
	if subRes.Account.Tier != TierTeam || subRes.Quotas.MaxScansPerMonth != 500 {
		t.Errorf("unexpected subscription response: %+v", subRes)
	}

	// 2. GET /api/v1/billing/usage
	resp, err = http.Get(server.URL + "/api/v1/billing/usage?org_id=" + orgID)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("failed to get usage: resp=%+v, err=%v", resp, err)
	}
	var usageRes struct {
		Usage  UsageMetrics `json:"usage"`
		Quotas TierQuotas   `json:"quotas"`
		Tier   PricingTier  `json:"tier"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&usageRes)
	if usageRes.Tier != TierTeam {
		t.Errorf("unexpected usage tier: %s", usageRes.Tier)
	}
}
