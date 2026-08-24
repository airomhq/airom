package owasp

import (
	"fmt"
	"strings"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Auditor analyzes an AIBOM inventory for OWASP LLM Top 10 vulnerabilities.
type Auditor struct{}

// NewAuditor constructs an OWASP LLM auditor.
func NewAuditor() *Auditor {
	return &Auditor{}
}

// Audit evaluates the inventory against all 10 OWASP LLM categories.
func (a *Auditor) Audit(inv *airom.Inventory) OWASPScorecard {
	scorecard := OWASPScorecard{
		CategoryPassMap: make(map[OWASPCategory]bool),
		AuditedAt:       time.Now().UTC(),
	}

	// Initialize all categories to passing
	categories := []OWASPCategory{
		LLM01_PromptInjection, LLM02_SensitiveDataExposure, LLM03_SupplyChain,
		LLM04_DataModelPoisoning, LLM05_ImproperOutputHandling, LLM06_ExcessiveAgency,
		LLM07_SystemPromptLeakage, LLM08_VectorEmbeddingWeakness, LLM09_Misinformation,
		LLM10_UnboundedConsumption,
	}
	for _, cat := range categories {
		scorecard.CategoryPassMap[cat] = true
	}

	if inv == nil {
		return scorecard
	}

	var findings []OWASPFinding

	for _, c := range inv.Components {
		// Check LLM03 / LLM04: Pickle serialization risks
		for _, r := range c.Risks {
			if strings.Contains(strings.ToLower(string(r.ID)), "pickle") || r.ID == airom.RiskPickleImport || r.ID == airom.RiskUnsafeLoad {
				findings = append(findings, OWASPFinding{
					ID:          fmt.Sprintf("owasp-pickle-%s", c.ID),
					Category:    LLM03_SupplyChain,
					Severity:    "CRITICAL",
					Title:       "Insecure Model Deserialization (Pickle Execution Risk)",
					Description: fmt.Sprintf("Model component %s utilizes pickle weights prone to arbitrary code execution.", c.Name),
					Remediation: "Migrate weights to Safetensors format.",
					ComponentID: string(c.ID),
				})
				scorecard.CategoryPassMap[LLM03_SupplyChain] = false
				scorecard.CategoryPassMap[LLM04_DataModelPoisoning] = false
			}

			if r.ID == airom.RiskAgenticUnconstrainedTool || r.ID == airom.RiskAgenticInsecureExec {
				findings = append(findings, OWASPFinding{
					ID:          fmt.Sprintf("owasp-agency-%s", c.ID),
					Category:    LLM06_ExcessiveAgency,
					Severity:    "HIGH",
					Title:       "Excessive Agency & Unconstrained Tool Execution",
					Description: fmt.Sprintf("Agentic component %s allows unconstrained tool invocations.", c.Name),
					Remediation: "Enforce AIROM Runtime Gateway circuit breaker with human approval gates.",
					ComponentID: string(c.ID),
				})
				scorecard.CategoryPassMap[LLM06_ExcessiveAgency] = false
			}
		}

		// Check MCP tool server naming
		if strings.Contains(strings.ToLower(c.Name), "mcp") && (c.Kind == airom.KindInfra || c.Kind == airom.KindService || c.Kind == airom.KindLibrary) {
			findings = append(findings, OWASPFinding{
				ID:          fmt.Sprintf("owasp-mcp-%s", c.ID),
				Category:    LLM06_ExcessiveAgency,
				Severity:    "HIGH",
				Title:       "Autonomous Tool Execution without Confirmation Barrier",
				Description: fmt.Sprintf("Tool server %s exposes execution actions without explicit user approval gates.", c.Name),
				Remediation: "Implement AIROM Runtime Gateway circuit breaker with human-in-the-loop approvals.",
				ComponentID: string(c.ID),
			})
			scorecard.CategoryPassMap[LLM06_ExcessiveAgency] = false
		}

		// Check LLM10: Unbounded Consumption (missing max_tokens limit in model facet)
		if c.Model != nil {
			hasMaxTokens := false
			for _, p := range c.Model.GenerationParams {
				if strings.ToLower(p.Name) == "max_tokens" {
					hasMaxTokens = true
					break
				}
			}
			if !hasMaxTokens {
				findings = append(findings, OWASPFinding{
					ID:          fmt.Sprintf("owasp-unbounded-%s", c.ID),
					Category:    LLM10_UnboundedConsumption,
					Severity:    "MEDIUM",
					Title:       "Unbounded Generation Parameter (Missing max_tokens)",
					Description: fmt.Sprintf("Model call %s does not declare a strict max_tokens ceiling, creating DoS/cost runaway vulnerability.", c.Name),
					Remediation: "Declare max_tokens parameter or enforce gateway clamping.",
					ComponentID: string(c.ID),
				})
				scorecard.CategoryPassMap[LLM10_UnboundedConsumption] = false
			}
		}
	}

	scorecard.Findings = findings
	scorecard.TotalFindings = len(findings)

	failedCategories := 0
	for _, passed := range scorecard.CategoryPassMap {
		if !passed {
			failedCategories++
		}
	}
	scorecard.RiskScore = float64(failedCategories) * 10.0

	return scorecard
}
