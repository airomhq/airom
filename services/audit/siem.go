package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatForDatadog converts an AuditEvent into Datadog Logs API JSON payload.
func FormatForDatadog(e *AuditEvent) ([]byte, error) {
	tags := fmt.Sprintf("env:production,org:%s,soc2:%s,severity:%s",
		e.OrgID, string(e.SOC2Control), strings.ToLower(string(e.Severity)),
	)
	if e.UserID != "" {
		tags += fmt.Sprintf(",user:%s", e.UserID)
	}

	payload := DatadogEvent{
		DDSource:  "airom-governance",
		DDService: "airom-audit-engine",
		Hostname:  "airom-vault",
		Message:   fmt.Sprintf("[%s] %s on %s by %s (SOC2: %s)", e.Severity, e.Action, e.Resource, e.UserID, e.SOC2Control),
		Status:    strings.ToLower(string(e.Severity)),
		Timestamp: e.Timestamp.UnixMilli(),
		Tags:      tags,
		Data: map[string]interface{}{
			"id":           e.ID,
			"org_id":       e.OrgID,
			"user_id":      e.UserID,
			"action":       e.Action,
			"resource":     e.Resource,
			"soc2_control": string(e.SOC2Control),
			"ip_address":   e.IPAddress,
			"user_agent":   e.UserAgent,
			"details":      e.Details,
			"signature":    e.Signature,
		},
	}
	return json.Marshal(payload)
}

// FormatForSplunk converts an AuditEvent into Splunk HEC JSON payload.
func FormatForSplunk(e *AuditEvent) ([]byte, error) {
	payload := SplunkHECEvent{
		Time:       e.Timestamp.Unix(),
		Host:       "airom-audit-engine",
		Source:     "airom:compliance",
		SourceType: "airom:audit:json",
		Event: map[string]interface{}{
			"id":           e.ID,
			"org_id":       e.OrgID,
			"user_id":      e.UserID,
			"action":       e.Action,
			"resource":     e.Resource,
			"severity":     string(e.Severity),
			"soc2_control": string(e.SOC2Control),
			"timestamp":    e.Timestamp.Format("2006-01-02T15:04:05.000Z"),
			"ip_address":   e.IPAddress,
			"user_agent":   e.UserAgent,
			"details":      e.Details,
			"signature":    e.Signature,
		},
	}
	return json.Marshal(payload)
}

// FormatForWebhook converts an AuditEvent into standard Webhook JSON payload.
func FormatForWebhook(e *AuditEvent) ([]byte, error) {
	return json.Marshal(e)
}
