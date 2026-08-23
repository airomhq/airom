package compliance

import (
	"sort"

	"github.com/airomhq/airom/pkg/airom"
)

// HarmonizedStandardCategory groups equivalent control domains across global jurisdictions.
type HarmonizedStandardCategory string

const (
	CategoryInventoryAndClassification HarmonizedStandardCategory = "SYSTEM_INVENTORY"
	CategoryDataGovernance             HarmonizedStandardCategory = "DATA_GOVERNANCE"
	CategoryRiskManagement             HarmonizedStandardCategory = "RISK_MANAGEMENT"
	CategorySecurityAndRobustness      HarmonizedStandardCategory = "SECURITY_ROBUSTNESS"
	CategoryHumanOversight             HarmonizedStandardCategory = "HUMAN_OVERSIGHT"
	CategoryIncidentMonitoring         HarmonizedStandardCategory = "INCIDENT_MONITORING"
)

// CategoryStatus aggregates multi-framework control status for a harmonized category.
type CategoryStatus struct {
	Category    HarmonizedStandardCategory `json:"category"`
	MetCount    int                        `json:"met_count"`
	GapCount    int                        `json:"gap_count"`
	ManualCount int                        `json:"manual_count"`
	State       airom.ControlState         `json:"state"`
}

// HarmonizationReport represents the unified cross-jurisdictional compliance evaluation.
type HarmonizationReport struct {
	FrameworksEvaluated   []string                                      `json:"frameworks_evaluated"`
	TotalControls         int                                           `json:"total_controls"`
	TotalMet              int                                           `json:"total_met"`
	TotalGap              int                                           `json:"total_gap"`
	TotalManual           int                                           `json:"total_manual"`
	HarmonizedReadiness   float64                                       `json:"harmonized_readiness_score"` // 0.0 - 100.0
	SharedEvidenceMap     map[airom.ID][]string                         `json:"shared_evidence_map"`        // ComponentID -> []FrameworkControlIDs
	CrossJurisdictionGaps map[airom.ID][]string                         `json:"cross_jurisdiction_gaps"`    // ComponentID -> []ViolatingFrameworks
	CategorySummaries     map[HarmonizedStandardCategory]CategoryStatus `json:"category_summaries"`
}

// GlobalStandardHarmonizer coordinates cross-standard equivalence evaluation.
type GlobalStandardHarmonizer struct {
	categoryRules map[string]HarmonizedStandardCategory
}

// NewHarmonizer initializes the global compliance harmonizer with standard cross-walk taxonomies.
func NewHarmonizer() *GlobalStandardHarmonizer {
	rules := map[string]HarmonizedStandardCategory{
		// System Inventory & Classification
		"MAP-2.1":                     CategoryInventoryAndClassification,
		"co.ai-act.impact-assessment": CategoryInventoryAndClassification,
		"eu.ai-act.title3.technical-documentation": CategoryInventoryAndClassification,
		"iso-42001.clause8.operational-inventory":  CategoryInventoryAndClassification,
		"canada-aida.high-impact-inventory":        CategoryInventoryAndClassification,
		"ca.ab2013.training-data-summary":          CategoryInventoryAndClassification,
		"nyc.ll144.bias-audit":                     CategoryInventoryAndClassification,

		// Data Governance & Quality
		"eu.ai-act.title3.data-governance":  CategoryDataGovernance,
		"iso-42001.annex-a.data-governance": CategoryDataGovernance,
		"canada-aida.data-governance":       CategoryDataGovernance,

		// Risk Management
		"GOVERN-1.1":                           CategoryRiskManagement,
		"co.ai-act.risk-mgmt":                  CategoryRiskManagement,
		"eu.ai-act.title3.risk-mgmt-system":    CategoryRiskManagement,
		"iso-42001.clause6.ai-risk-assessment": CategoryRiskManagement,
		"canada-aida.bias-mitigation":          CategoryRiskManagement,

		// Security & Robustness
		"MEASURE-2.7":                           CategorySecurityAndRobustness,
		"T11":                                   CategorySecurityAndRobustness,
		"eu.ai-act.title2.prohibited-practices": CategorySecurityAndRobustness,
		"eu.ai-act.title3.accuracy-robustness-cybersecurity": CategorySecurityAndRobustness,
		"iso-42001.annex-a.system-security":                  CategorySecurityAndRobustness,
		"canada-aida.system-security":                        CategorySecurityAndRobustness,

		// Human Oversight
		"eu.ai-act.title3.human-oversight": CategoryHumanOversight,
		"co.ai-act.consumer-notice":        CategoryHumanOversight,

		// Incident Monitoring
		"co.ai-act.incident-reporting":         CategoryIncidentMonitoring,
		"eu.ai-act.title3.record-keeping-logs": CategoryIncidentMonitoring,
		"canada-aida.incident-monitoring":      CategoryIncidentMonitoring,
	}

	return &GlobalStandardHarmonizer{categoryRules: rules}
}

// Harmonize evaluates compliance outcomes across multiple jurisdictions to generate a unified multi-standard report.
func (h *GlobalStandardHarmonizer) Harmonize(inv *airom.Inventory, results []airom.ComplianceResult) *HarmonizationReport {
	report := &HarmonizationReport{
		SharedEvidenceMap:     make(map[airom.ID][]string),
		CrossJurisdictionGaps: make(map[airom.ID][]string),
		CategorySummaries:     make(map[HarmonizedStandardCategory]CategoryStatus),
	}

	categories := []HarmonizedStandardCategory{
		CategoryInventoryAndClassification,
		CategoryDataGovernance,
		CategoryRiskManagement,
		CategorySecurityAndRobustness,
		CategoryHumanOversight,
		CategoryIncidentMonitoring,
	}

	for _, cat := range categories {
		report.CategorySummaries[cat] = CategoryStatus{
			Category: cat,
			State:    airom.ControlMet,
		}
	}

	for _, res := range results {
		report.FrameworksEvaluated = append(report.FrameworksEvaluated, res.Framework)

		for _, ctrl := range res.Controls {
			report.TotalControls++
			switch ctrl.State {
			case airom.ControlMet:
				report.TotalMet++
			case airom.ControlGap:
				report.TotalGap++
			case airom.ControlManual:
				report.TotalManual++
			}

			// Map Category
			cat, hasCat := h.categoryRules[ctrl.ID]
			if !hasCat {
				cat = CategoryInventoryAndClassification
			}

			catStat := report.CategorySummaries[cat]
			switch ctrl.State {
			case airom.ControlMet:
				catStat.MetCount++
			case airom.ControlGap:
				catStat.GapCount++
				catStat.State = airom.ControlGap
			case airom.ControlManual:
				catStat.ManualCount++
				if catStat.State != airom.ControlGap {
					catStat.State = airom.ControlManual
				}
			}
			report.CategorySummaries[cat] = catStat

			// Map Shared Evidence
			for _, evID := range ctrl.Evidence {
				label := res.Framework + ":" + ctrl.ID
				report.SharedEvidenceMap[evID] = append(report.SharedEvidenceMap[evID], label)
			}

			// Map Cross-Jurisdiction Gaps
			for _, gapID := range ctrl.Counter {
				report.CrossJurisdictionGaps[gapID] = append(report.CrossJurisdictionGaps[gapID], res.Framework)
			}
		}
	}

	sort.Strings(report.FrameworksEvaluated)

	// Deduplicate slice values
	for k, v := range report.SharedEvidenceMap {
		report.SharedEvidenceMap[k] = dedupeStrings(v)
	}
	for k, v := range report.CrossJurisdictionGaps {
		report.CrossJurisdictionGaps[k] = dedupeStrings(v)
	}

	// Calculate Harmonized Readiness Score: (Met / (Met + Gap)) * 100%
	evaluable := report.TotalMet + report.TotalGap
	if evaluable > 0 {
		report.HarmonizedReadiness = (float64(report.TotalMet) / float64(evaluable)) * 100.0
	} else {
		report.HarmonizedReadiness = 100.0
	}

	return report
}

// Harmonize evaluates compliance outcomes using the default harmonizer.
func Harmonize(inv *airom.Inventory, results []airom.ComplianceResult) *HarmonizationReport {
	return NewHarmonizer().Harmonize(inv, results)
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
