package shadowai

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *ShadowAIDetector) hasFastCandidate(pathLower, contentLower string, platform SaaSPlatform) bool {
	switch platform {
	case PlatformOpenAI:
		return strings.Contains(contentLower, "sk-") || strings.Contains(contentLower, "openai") || strings.Contains(pathLower, "openai")
	case PlatformAnthropic:
		return strings.Contains(contentLower, "sk-ant") || strings.Contains(contentLower, "anthropic") || strings.Contains(pathLower, "anthropic")
	case PlatformCursor:
		return strings.Contains(pathLower, "cursor") || strings.Contains(contentLower, "cursor")
	case PlatformGitHubCopilot:
		return strings.Contains(pathLower, "copilot") || strings.Contains(contentLower, "copilot")
	case PlatformNotionAI:
		return strings.Contains(contentLower, "ntn_") || strings.Contains(contentLower, "notion") || strings.Contains(pathLower, "notion")
	case PlatformSlackAI:
		return strings.Contains(contentLower, "slack") || strings.Contains(pathLower, "slack")
	case PlatformPerplexity:
		return strings.Contains(contentLower, "pplx") || strings.Contains(contentLower, "perplexity") || strings.Contains(pathLower, "perplexity")
	case PlatformHuggingFace:
		return strings.Contains(contentLower, "hf_") || strings.Contains(contentLower, "huggingface") || strings.Contains(pathLower, "huggingface")
	default:
		return true
	}
}

// FileEntry represents a file path and its text content for shadow AI inspection.
type FileEntry struct {
	Path    string
	Content string
}

// DetectorOptions contains configuration for scanning shadow AI assets.
type DetectorOptions struct {
	OrganizationID    string
	ApprovedPlatforms []SaaSPlatform
	EnforceZDRPolicy  bool
}

// ShadowAIDetector scans file contents, IDE configurations, and environment secrets for undeclared SaaS AI tools.
type ShadowAIDetector struct {
	signatures []toolSignature
}

type toolSignature struct {
	platform SaaSPlatform
	toolName string
	category UsageCategory
	pattern  *regexp.Regexp
	severity RiskSeverity
	risks    []DataExposureRisk
	policy   string
	remedy   string
}

// NewShadowAIDetector constructs a new detector with preloaded SaaS AI signatures.
func NewShadowAIDetector() *ShadowAIDetector {
	d := &ShadowAIDetector{}
	d.initSignatures()
	return d
}

func (d *ShadowAIDetector) initSignatures() {
	d.signatures = []toolSignature{
		{
			platform: PlatformOpenAI,
			toolName: "OpenAI Direct API Key",
			category: CategoryAPIToken,
			pattern:  regexp.MustCompile(`(?i)(?:sk-proj-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{32,}|openai[_\-\s]*api[_\-\s]*key\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,})`),
			severity: RiskCritical,
			risks:    []DataExposureRisk{ExposureCodeExfiltration, ExposurePIILeakage, ExposureIPLoss, ExposureModelTraining},
			policy:   "CO SB 24-205 § 6-1-1703 & NIST AI RMF GOVERN 1.1: Unvetted raw OpenAI key detected in codebase.",
			remedy:   "Revoke exposed key immediately; route requests through AIROM Runtime Security Gateway with Zero-Data-Retention.",
		},
		{
			platform: PlatformAnthropic,
			toolName: "Anthropic Claude API Key",
			category: CategoryAPIToken,
			pattern:  regexp.MustCompile(`(?i)(?:sk-ant-api03-[a-zA-Z0-9_\-]{20,}|anthropic[_\-\s]*api[_\-\s]*key\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,})`),
			severity: RiskCritical,
			risks:    []DataExposureRisk{ExposureCodeExfiltration, ExposurePIILeakage, ExposureIPLoss},
			policy:   "ISO/IEC 42001 A.6.2: Direct unmanaged Anthropic endpoint usage without central token governance.",
			remedy:   "Migrate API integration to AIROM Gateway proxy with PII redaction active.",
		},
		{
			platform: PlatformCursor,
			toolName: "Cursor AI IDE Rules & Config",
			category: CategoryIDETooling,
			pattern:  regexp.MustCompile(`(?i)(?:\.cursorrules|\.cursor/|cursor[_\-\s]*api[_\-\s]*key)`),
			severity: RiskHigh,
			risks:    []DataExposureRisk{ExposureCodeExfiltration, ExposureIPLoss},
			policy:   "Enterprise Code Governance Policy: Undeclared Cursor AI configuration detected in repository.",
			remedy:   "Register Cursor AI in AIROM enterprise asset inventory; verify Privacy Mode (Zero Data Retention) is enabled.",
		},
		{
			platform: PlatformGitHubCopilot,
			toolName: "GitHub Copilot Config",
			category: CategoryIDETooling,
			pattern:  regexp.MustCompile(`(?i)(?:github\.copilot|\.copilot-ignore|copilot-chat)`),
			severity: RiskMedium,
			risks:    []DataExposureRisk{ExposureCodeExfiltration},
			policy:   "AI Asset Inventory: GitHub Copilot usage identified.",
			remedy:   "Verify enterprise Business Copilot seat assignment with public code suggestions disabled.",
		},
		{
			platform: PlatformNotionAI,
			toolName: "Notion AI Workspace Integration",
			category: CategoryProductivitySaaS,
			pattern:  regexp.MustCompile(`(?i)(?:ntn_[a-zA-Z0-9]{20,}|notion-ai|api\.notion\.com/v1/ai)`),
			severity: RiskHigh,
			risks:    []DataExposureRisk{ExposurePIILeakage, ExposureIPLoss},
			policy:   "Data Protection Assessment: Unauthorized Notion AI integration with corporate workspace access.",
			remedy:   "Submit Data Protection Assessment (DPA) to AIROM ComplianceDB before connecting to customer notes.",
		},
		{
			platform: PlatformSlackAI,
			toolName: "Slack AI Automated Summaries",
			category: CategoryProductivitySaaS,
			pattern:  regexp.MustCompile(`(?i)(?:slack\.ai|xoxb-slack-ai|slack-bot-ai-summarizer)`),
			severity: RiskHigh,
			risks:    []DataExposureRisk{ExposurePIILeakage, ExposureCodeExfiltration},
			policy:   "Confidential Communication Safeguard: Slack AI automated message summarization active on internal channels.",
			remedy:   "Verify channels containing customer PII or confidential source code have Slack AI opt-outs enabled.",
		},
		{
			platform: PlatformPerplexity,
			toolName: "Perplexity AI API / Search",
			category: CategoryAPIToken,
			pattern:  regexp.MustCompile(`(?i)(?:pplx-[a-zA-Z0-9]{20,}|api\.perplexity\.ai)`),
			severity: RiskHigh,
			risks:    []DataExposureRisk{ExposureIPLoss, ExposureUnencryptedPrompt},
			policy:   "Statutory AI Inventory: Direct Perplexity AI query endpoint discovered.",
			remedy:   "Audit prompts dispatched to Perplexity for intellectual property clearance.",
		},
		{
			platform: PlatformHuggingFace,
			toolName: "HuggingFace Write/User Token",
			category: CategoryAPIToken,
			pattern:  regexp.MustCompile(`(?i)(?:hf_[a-zA-Z0-9]{20,}|huggingface_token)`),
			severity: RiskMedium,
			risks:    []DataExposureRisk{ExposureIPLoss, ExposureModelTraining},
			policy:   "Model Supply Chain Governance: HuggingFace write token detected in build scripts.",
			remedy:   "Enforce read-only scoped tokens for model inference; restrict model upload capabilities to CI service accounts.",
		},
	}
}

// ScanFiles inspects a collection of files and generates an aggregated Shadow AI inventory.
func (d *ShadowAIDetector) ScanFiles(entries []FileEntry, opts DetectorOptions) (*ShadowAIInventory, error) {
	if opts.OrganizationID == "" {
		opts.OrganizationID = "default-org"
	}

	approvedMap := make(map[SaaSPlatform]bool)
	for _, app := range opts.ApprovedPlatforms {
		approvedMap[app] = true
	}

	inventory := &ShadowAIInventory{
		InventoryID:    fmt.Sprintf("inv_%s", randHex(6)),
		OrganizationID: opts.OrganizationID,
		ScannedAt:      time.Now().UTC(),
		Findings:       make([]ShadowAIFinding, 0),
	}

	seenKeyMap := make(map[string]bool)

	for _, entry := range entries {
		pathLower := strings.ToLower(entry.Path)
		contentLower := strings.ToLower(entry.Content)

		// Scan against path and content
		for _, sig := range d.signatures {
			if !d.hasFastCandidate(pathLower, contentLower, sig.platform) {
				continue
			}

			var matched bool
			var snippet string

			// Path check (e.g. .cursorrules)
			if sig.pattern.MatchString(entry.Path) {
				matched = true
				snippet = entry.Path
			} else if sig.pattern.MatchString(entry.Content) {
				matched = true
				loc := sig.pattern.FindStringIndex(entry.Content)
				if loc != nil {
					raw := entry.Content[loc[0]:loc[1]]
					if len(raw) > 12 {
						snippet = raw[:6] + "..." + raw[len(raw)-4:]
					} else {
						snippet = "discovered-token"
					}
				}
			}

			if matched {
				dedupKey := fmt.Sprintf("%s|%s|%s", sig.platform, entry.Path, sig.category)
				if seenKeyMap[dedupKey] {
					continue
				}
				seenKeyMap[dedupKey] = true

				severity := sig.severity
				if approvedMap[sig.platform] {
					severity = RiskApproved
				}

				finding := ShadowAIFinding{
					FindingID:         fmt.Sprintf("shd_%s", randHex(6)),
					Platform:          sig.platform,
					ToolName:          sig.toolName,
					Category:          sig.category,
					Location:          entry.Path,
					TokenSnippet:      snippet,
					FirstSeenAt:       inventory.ScannedAt,
					Severity:          severity,
					ExposureRisks:     sig.risks,
					PolicyViolation:   sig.policy,
					RemediationAction: sig.remedy,
					ZeroDataRetention: approvedMap[sig.platform],
				}
				finding.ComputeHash()
				inventory.Findings = append(inventory.Findings, finding)

				switch severity {
				case RiskCritical:
					inventory.CriticalCount++
				case RiskHigh:
					inventory.HighCount++
				case RiskMedium:
					inventory.MediumCount++
				case RiskLow:
					inventory.LowCount++
				case RiskApproved:
					inventory.ApprovedCount++
				}
			}
		}
	}

	inventory.TotalDiscovered = len(inventory.Findings)
	inventory.ComputeInventoryHash()
	return inventory, nil
}
