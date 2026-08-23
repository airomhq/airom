package shadowai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// SaaSPlatform represents third-party SaaS or developer AI tools.
type SaaSPlatform string

const (
	PlatformOpenAI        SaaSPlatform = "OPENAI"
	PlatformAnthropic     SaaSPlatform = "ANTHROPIC"
	PlatformGitHubCopilot SaaSPlatform = "GITHUB_COPILOT"
	PlatformCursor        SaaSPlatform = "CURSOR_AI"
	PlatformNotionAI      SaaSPlatform = "NOTION_AI"
	PlatformSlackAI       SaaSPlatform = "SLACK_AI"
	PlatformFigmaAI       SaaSPlatform = "FIGMA_AI"
	PlatformPerplexity    SaaSPlatform = "PERPLEXITY"
	PlatformGrammarly     SaaSPlatform = "GRAMMARLY_AI"
	PlatformDeepL         SaaSPlatform = "DEEPL_AI"
	PlatformMidjourney    SaaSPlatform = "MIDJOURNEY"
	PlatformHuggingFace   SaaSPlatform = "HUGGINGFACE"
	PlatformGlean         SaaSPlatform = "GLEAN_AI"
	PlatformJasper        SaaSPlatform = "JASPER_AI"
	PlatformCustom        SaaSPlatform = "CUSTOM_SAAS_AI"
)

// RiskSeverity indicates governance and security severity of a Shadow AI finding.
type RiskSeverity string

const (
	RiskCritical RiskSeverity = "CRITICAL" // Unvetted code/PII exfiltration, active developer key without ZDR
	RiskHigh     RiskSeverity = "HIGH"     // Unauthorized generative AI tool with training data retention
	RiskMedium   RiskSeverity = "MEDIUM"   // Productivity AI tool without enterprise SSO gating
	RiskLow      RiskSeverity = "LOW"      // Generic translation/formatting AI with minimal sensitive data
	RiskApproved RiskSeverity = "APPROVED" // Vetted and whitelisted by corporate compliance
)

// DataExposureRisk flags specific data leakage vectors.
type DataExposureRisk string

const (
	ExposureCodeExfiltration  DataExposureRisk = "CODE_EXFILTRATION"
	ExposurePIILeakage        DataExposureRisk = "PII_LEAKAGE"
	ExposureIPLoss            DataExposureRisk = "IP_LOSS"
	ExposureModelTraining     DataExposureRisk = "UNVETTED_TRAINING_USE"
	ExposureUnencryptedPrompt DataExposureRisk = "UNENCRYPTED_PROMPT"
)

// UsageCategory represents how the SaaS AI tool is integrated.
type UsageCategory string

const (
	CategoryIDETooling       UsageCategory = "IDE_EXTENSION"
	CategoryAPIToken         UsageCategory = "RAW_API_KEY"
	CategoryProductivitySaaS UsageCategory = "SAAS_WORKSPACE"
	CategoryCIPipeline       UsageCategory = "CI_CD_SECRET"
	CategoryBrowserExtension UsageCategory = "BROWSER_EXTENSION"
)

// ShadowAIFinding represents a single discovered unauthorized or unvetted AI asset.
type ShadowAIFinding struct {
	FindingID         string             `json:"finding_id"`
	Platform          SaaSPlatform       `json:"platform"`
	ToolName          string             `json:"tool_name"`
	Category          UsageCategory      `json:"category"`
	Location          string             `json:"location"`      // File path, config key, or repo URL
	TokenSnippet      string             `json:"token_snippet"` // Masked snippet (e.g. sk-proj-...abc)
	FirstSeenAt       time.Time          `json:"first_seen_at"`
	Severity          RiskSeverity       `json:"severity"`
	ExposureRisks     []DataExposureRisk `json:"exposure_risks"`
	PolicyViolation   string             `json:"policy_violation"`
	RemediationAction string             `json:"remediation_action"`
	ZeroDataRetention bool               `json:"zero_data_retention"`
	FindingHash       string             `json:"finding_hash"`
}

// ComputeHash calculates a deterministic SHA-256 fingerprint for the shadow AI finding.
func (f *ShadowAIFinding) ComputeHash() string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		f.FindingID, f.Platform, f.Category, f.Location, f.Severity, f.PolicyViolation)
	sum := sha256.Sum256([]byte(raw))
	f.FindingHash = hex.EncodeToString(sum[:])
	return f.FindingHash
}

// ShadowAIInventory aggregates discovered shadow AI tools across an enterprise organization.
type ShadowAIInventory struct {
	InventoryID     string            `json:"inventory_id"`
	OrganizationID  string            `json:"organization_id"`
	ScannedAt       time.Time         `json:"scanned_at"`
	TotalDiscovered int               `json:"total_discovered"`
	CriticalCount   int               `json:"critical_count"`
	HighCount       int               `json:"high_count"`
	MediumCount     int               `json:"medium_count"`
	LowCount        int               `json:"low_count"`
	ApprovedCount   int               `json:"approved_count"`
	Findings        []ShadowAIFinding `json:"findings"`
	InventoryHash   string            `json:"inventory_hash"`
}

// ComputeInventoryHash calculates a composite SHA-256 hash over all findings in the inventory.
func (inv *ShadowAIInventory) ComputeInventoryHash() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%d|%d|%d\n",
		inv.InventoryID, inv.OrganizationID, inv.ScannedAt.UTC().Format(time.RFC3339),
		inv.TotalDiscovered, inv.CriticalCount, inv.HighCount)
	for _, f := range inv.Findings {
		_, _ = fmt.Fprintf(h, "%s:%s:%s:%s\n", f.FindingID, f.Platform, f.Severity, f.FindingHash)
	}
	inv.InventoryHash = hex.EncodeToString(h.Sum(nil))
	return inv.InventoryHash
}
