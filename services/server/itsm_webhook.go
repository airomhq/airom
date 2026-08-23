package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ITSMConfig configures enterprise ticket dispatching for Jira and ServiceNow.
type ITSMConfig struct {
	// Jira Settings
	JiraEnabled    bool   `json:"jira_enabled"`
	JiraURL        string `json:"jira_url"`
	JiraUsername   string `json:"jira_username"`
	JiraAPIToken   string `json:"jira_api_token"`
	JiraProjectKey string `json:"jira_project_key"`
	JiraIssueType  string `json:"jira_issue_type"` // e.g. "Bug", "Task", "Security Vulnerability"

	// ServiceNow Settings
	ServiceNowEnabled         bool   `json:"servicenow_enabled"`
	ServiceNowURL             string `json:"servicenow_url"`
	ServiceNowUsername        string `json:"servicenow_username"`
	ServiceNowPassword        string `json:"servicenow_password"`
	ServiceNowTable           string `json:"servicenow_table"`            // default: "incident"
	ServiceNowAssignmentGroup string `json:"servicenow_assignment_group"` // optional

	AutoResolve bool `json:"auto_resolve"`
}

// ComplianceIncident represents a regulatory compliance gap or security defect requiring ITSM tracking.
type ComplianceIncident struct {
	ID           string    `json:"id"`
	RepoID       string    `json:"repo_id"`
	OrgID        string    `json:"org_id"`
	Framework    string    `json:"framework"` // e.g. "EU-AI-Act", "CO-SB-24-205", "ISO-42001"
	ControlID    string    `json:"control_id"`
	ControlTitle string    `json:"control_title"`
	Severity     string    `json:"severity"` // "Critical", "High", "Medium", "Low"
	Description  string    `json:"description"`
	Status       string    `json:"status"` // "gap", "met"
	CreatedAt    time.Time `json:"created_at"`
}

// ITSMResponse captures external ticket identifiers returned by Jira or ServiceNow.
type ITSMResponse struct {
	Provider   string `json:"provider"` // "jira" or "servicenow"
	ExternalID string `json:"external_id"`
	TicketURL  string `json:"ticket_url"`
	Status     string `json:"status"`
}

// ITSMConnector dispatches and auto-resolves enterprise ITSM incidents.
type ITSMConnector struct {
	config ITSMConfig
	client *http.Client
}

// NewITSMConnector initializes an ITSM integration connector.
func NewITSMConnector(cfg ITSMConfig, httpClient *http.Client) *ITSMConnector {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.JiraIssueType == "" {
		cfg.JiraIssueType = "Bug"
	}
	if cfg.ServiceNowTable == "" {
		cfg.ServiceNowTable = "incident"
	}
	return &ITSMConnector{
		config: cfg,
		client: httpClient,
	}
}

// DispatchIncident sends a new compliance defect to configured ITSM systems.
func (c *ITSMConnector) DispatchIncident(ctx context.Context, inc ComplianceIncident) ([]*ITSMResponse, error) {
	if inc.ID == "" {
		return nil, errors.New("incident ID cannot be empty")
	}

	var responses []*ITSMResponse

	// 1. Dispatch to Jira if enabled
	if c.config.JiraEnabled && c.config.JiraURL != "" {
		resp, err := c.dispatchJira(ctx, inc)
		if err != nil {
			return responses, fmt.Errorf("jira dispatch failed: %w", err)
		}
		responses = append(responses, resp)
	}

	// 2. Dispatch to ServiceNow if enabled
	if c.config.ServiceNowEnabled && c.config.ServiceNowURL != "" {
		resp, err := c.dispatchServiceNow(ctx, inc)
		if err != nil {
			return responses, fmt.Errorf("servicenow dispatch failed: %w", err)
		}
		responses = append(responses, resp)
	}

	return responses, nil
}

func (c *ITSMConnector) dispatchJira(ctx context.Context, inc ComplianceIncident) (*ITSMResponse, error) {
	endpoint := fmt.Sprintf("%s/rest/api/2/issue", strings.TrimRight(c.config.JiraURL, "/"))

	priority := "Medium"
	switch strings.ToLower(inc.Severity) {
	case "critical":
		priority = "Highest"
	case "high":
		priority = "High"
	case "low":
		priority = "Low"
	}

	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": c.config.JiraProjectKey,
			},
			"summary": fmt.Sprintf("[AIROM %s] Compliance Gap: %s (%s)", inc.Framework, inc.ControlTitle, inc.ControlID),
			"description": fmt.Sprintf("*AI Governance Gap Detected by AIROM*\n\n"+
				"*Repository:* %s\n"+
				"*Organization:* %s\n"+
				"*Framework:* %s\n"+
				"*Control ID:* %s\n"+
				"*Severity:* %s\n\n"+
				"*Details:*\n%s\n",
				inc.RepoID, inc.OrgID, inc.Framework, inc.ControlID, inc.Severity, inc.Description),
			"issuetype": map[string]string{
				"name": c.config.JiraIssueType,
			},
			"priority": map[string]string{
				"name": priority,
			},
			"labels": []string{"airom-compliance", "ai-governance", strings.ToLower(inc.Framework)},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(c.config.JiraUsername + ":" + c.config.JiraAPIToken))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jira returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &ITSMResponse{
		Provider:   "jira",
		ExternalID: result.Key,
		TicketURL:  fmt.Sprintf("%s/browse/%s", strings.TrimRight(c.config.JiraURL, "/"), result.Key),
		Status:     "created",
	}, nil
}

func (c *ITSMConnector) dispatchServiceNow(ctx context.Context, inc ComplianceIncident) (*ITSMResponse, error) {
	endpoint := fmt.Sprintf("%s/api/now/table/%s", strings.TrimRight(c.config.ServiceNowURL, "/"), c.config.ServiceNowTable)

	severityCode := "3" // Moderate
	switch strings.ToLower(inc.Severity) {
	case "critical":
		severityCode = "1" // High
	case "high":
		severityCode = "2" // Medium
	case "low":
		severityCode = "4" // Low
	}

	payload := map[string]interface{}{
		"short_description": fmt.Sprintf("[AIROM %s] Compliance Gap: %s", inc.Framework, inc.ControlTitle),
		"description": fmt.Sprintf("AIROM Governance Incident\nRepo: %s\nOrg: %s\nControl: %s (%s)\nSeverity: %s\n\n%s",
			inc.RepoID, inc.OrgID, inc.ControlTitle, inc.ControlID, inc.Severity, inc.Description),
		"impact":         severityCode,
		"urgency":        severityCode,
		"correlation_id": inc.ID,
		"category":       "Security",
	}
	if c.config.ServiceNowAssignmentGroup != "" {
		payload["assignment_group"] = c.config.ServiceNowAssignmentGroup
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(c.config.ServiceNowUsername + ":" + c.config.ServiceNowPassword))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("servicenow returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &ITSMResponse{
		Provider:   "servicenow",
		ExternalID: result.Result.Number,
		TicketURL:  fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s", strings.TrimRight(c.config.ServiceNowURL, "/"), c.config.ServiceNowTable, result.Result.SysID),
		Status:     "created",
	}, nil
}

// AutoResolveIncident sends an automated ticket resolution when a control transitions from gap to met.
func (c *ITSMConnector) AutoResolveIncident(ctx context.Context, provider, externalID, resolutionNote string) error {
	if !c.config.AutoResolve {
		return nil
	}

	switch strings.ToLower(provider) {
	case "jira":
		endpoint := fmt.Sprintf("%s/rest/api/2/issue/%s/comment", strings.TrimRight(c.config.JiraURL, "/"), externalID)
		payload := map[string]interface{}{
			"body": fmt.Sprintf("✅ *AIROM Automated Remediation Verified*\n\n%s\n\nIssue auto-resolved by AIROM Compliance Scanner at %s.",
				resolutionNote, time.Now().UTC().Format(time.RFC3339)),
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		auth := base64.StdEncoding.EncodeToString([]byte(c.config.JiraUsername + ":" + c.config.JiraAPIToken))
		req.Header.Set("Authorization", "Basic "+auth)
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("jira resolution comment returned status %d", resp.StatusCode)
		}
		return nil

	case "servicenow":
		endpoint := fmt.Sprintf("%s/api/now/table/%s/%s", strings.TrimRight(c.config.ServiceNowURL, "/"), c.config.ServiceNowTable, externalID)
		payload := map[string]interface{}{
			"state":       "6", // Resolved
			"close_code":  "Solved (Permanently)",
			"close_notes": fmt.Sprintf("Remediated in code scan: %s", resolutionNote),
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		auth := base64.StdEncoding.EncodeToString([]byte(c.config.ServiceNowUsername + ":" + c.config.ServiceNowPassword))
		req.Header.Set("Authorization", "Basic "+auth)
		resp, err := c.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("servicenow resolve returned status %d", resp.StatusCode)
		}
		return nil
	}

	return fmt.Errorf("unsupported ITSM provider: %s", provider)
}
