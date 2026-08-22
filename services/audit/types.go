// Package audit provides SOC 2 compliant immutable audit logging and SIEM event streaming.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Severity represents SOC 2 event severity level.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// SOC2Control maps to SOC 2 Trust Services Criteria.
type SOC2Control string

const (
	SOC2_CC6_1 SOC2Control = "CC6.1_LOGICAL_ACCESS"
	SOC2_CC6_2 SOC2Control = "CC6.2_USER_REGISTRATION"
	SOC2_CC6_6 SOC2Control = "CC6.6_SECURITY_EVENT_MONITORING"
	SOC2_CC6_8 SOC2Control = "CC6.8_THREAT_DETECTION"
	SOC2_CC7_2 SOC2Control = "CC7.2_SECURITY_INCIDENT_RESPONSE"
	SOC2_CC8_1 SOC2Control = "CC8.1_CHANGE_MANAGEMENT"
)

// SIEMDestination identifies target SIEM platform.
type SIEMDestination string

const (
	SIEMDatadog SIEMDestination = "datadog"
	SIEMSplunk  SIEMDestination = "splunk"
	SIEMWebhook SIEMDestination = "webhook"
)

// AuditEvent represents an immutable SOC 2 audit record.
type AuditEvent struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"org_id"`
	UserID      string                 `json:"user_id,omitempty"`
	Action      string                 `json:"action"`   // e.g. "AUTH_LOGIN", "KEY_ROTATED", "REPORT_CERTIFIED", "SCAN_EXECUTED"
	Resource    string                 `json:"resource"` // e.g. "repo:backend-ai", "doc:rep-il-123"
	Severity    Severity               `json:"severity"`
	SOC2Control SOC2Control            `json:"soc2_control"`
	Timestamp   time.Time              `json:"timestamp"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Signature   string                 `json:"signature"` // HMAC-SHA256 tamper-evident seal
}

// SIEMConfig configures export to external SIEM / log aggregator.
type SIEMConfig struct {
	ID          string          `json:"id"`
	OrgID       string          `json:"org_id"`
	Destination SIEMDestination `json:"destination"`
	EndpointURL string          `json:"endpoint_url"`
	APIKey      string          `json:"api_key,omitempty"`    // Datadog DD-API-KEY or Splunk HEC Token
	SecretKey   string          `json:"secret_key,omitempty"` // For Webhook HMAC verification
	Enabled     bool            `json:"enabled"`
	MaxRetries  int             `json:"max_retries"`
	BatchSize   int             `json:"batch_size"`
}

// ComputeSignature calculates the HMAC-SHA256 seal for an audit event.
func (e *AuditEvent) ComputeSignature(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d",
		e.ID, e.OrgID, e.UserID, e.Action, e.Resource, e.Severity, e.Timestamp.UnixNano(),
	)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature validates event integrity.
func (e *AuditEvent) VerifySignature(secret string) bool {
	expected := e.ComputeSignature(secret)
	return hmac.Equal([]byte(e.Signature), []byte(expected))
}

// DatadogEvent represents the payload format for Datadog Logs API.
type DatadogEvent struct {
	DDSource  string                 `json:"ddsource"`
	DDService string                 `json:"service"`
	Hostname  string                 `json:"hostname"`
	Message   string                 `json:"message"`
	Status    string                 `json:"status"`
	Timestamp int64                  `json:"timestamp"`
	Tags      string                 `json:"ddtags"`
	Data      map[string]interface{} `json:"data"`
}

// SplunkHECEvent represents the payload format for Splunk HTTP Event Collector.
type SplunkHECEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host"`
	Source     string                 `json:"source"`
	SourceType string                 `json:"sourcetype"`
	Index      string                 `json:"index,omitempty"`
	Event      map[string]interface{} `json:"event"`
}
