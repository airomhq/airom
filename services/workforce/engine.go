package workforce

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// WorkforceEngine calculates task automation exposure, displacement risks, and statutory duty-of-care obligations.
type WorkforceEngine struct{}

// NewWorkforceEngine creates a new WorkforceEngine instance.
func NewWorkforceEngine() *WorkforceEngine {
	return &WorkforceEngine{}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AssessWorkforceImpact performs comprehensive evaluation of AI capabilities against enterprise roles.
func (e *WorkforceEngine) AssessWorkforceImpact(
	orgID string,
	systemName string,
	capabilities []AISystemCapability,
	roles []RoleProfile,
	evaluatedAt time.Time,
) (*WorkforceAssessmentReport, error) {
	if orgID == "" {
		return nil, fmt.Errorf("organization_id is required")
	}
	if systemName == "" {
		systemName = "AI-System-Default"
	}
	if evaluatedAt.IsZero() {
		evaluatedAt = time.Now().UTC()
	}

	report := &WorkforceAssessmentReport{
		ReportID:          fmt.Sprintf("wfr_%s", randHex(6)),
		OrganizationID:    orgID,
		SystemName:        systemName,
		EvaluatedAt:       evaluatedAt,
		RoleAssessments:   make([]RoleImpactAssessment, 0, len(roles)),
		DutyOfCareNotices: make([]DutyOfCareNotice, 0),
		StatutoryFindings: make([]string, 0),
	}

	// Index automated tasks from capabilities
	automatedTaskMap := make(map[string]float64)
	var hasHighImpactDecisions bool

	for _, cap := range capabilities {
		if cap.HighImpactDecisions {
			hasHighImpactDecisions = true
		}
		autonomy := cap.AutonomyLevel
		if autonomy <= 0 {
			autonomy = 0.5 // Default assist level
		}
		for _, task := range cap.AutomatedTasks {
			taskNorm := strings.ToLower(strings.TrimSpace(task))
			if cur, ok := automatedTaskMap[taskNorm]; !ok || autonomy > cur {
				automatedTaskMap[taskNorm] = autonomy
			}
		}
	}

	var (
		totalHeadcount        int
		weightedExposureSum   float64
		aggregateDisplacedFTE float64
		aggregateRetrainHrs   int
		deptMap               = make(map[string]*DepartmentImpactSummary)
	)

	for _, role := range roles {
		if role.Headcount < 0 {
			role.Headcount = 0
		}
		totalHeadcount += role.Headcount

		// Calculate task exposure ratio
		var matchedTasksCount float64
		totalTasks := len(role.CoreTasks)
		if totalTasks == 0 {
			totalTasks = 1 // Prevent division by zero
		}

		for _, task := range role.CoreTasks {
			taskNorm := strings.ToLower(strings.TrimSpace(task))
			// Direct match or partial keyword match
			if weight, ok := automatedTaskMap[taskNorm]; ok {
				matchedTasksCount += weight
			} else {
				for autoTask, weight := range automatedTaskMap {
					if strings.Contains(taskNorm, autoTask) || strings.Contains(autoTask, taskNorm) {
						matchedTasksCount += weight * 0.8
						break
					}
				}
			}
		}

		exposure := (matchedTasksCount / float64(totalTasks)) * 100.0
		if exposure > 100.0 {
			exposure = 100.0
		}

		riskTier := e.classifyRiskTier(exposure)
		displacedFTE := float64(role.Headcount) * (exposure / 100.0) * 0.70
		retrainHrs := int(exposure * 1.5 * float64(role.Headcount))

		aggregateDisplacedFTE += displacedFTE
		aggregateRetrainHrs += retrainHrs
		weightedExposureSum += exposure * float64(role.Headcount)

		// Determine triggered statutory protections
		var triggeredStatutes []StatutoryProtection
		if hasHighImpactDecisions || role.Category == RoleCategoryHR {
			triggeredStatutes = append(triggeredStatutes, ProtectionColoradoAIA, ProtectionNYCAEDT, ProtectionEUAIAArticle6)
			if role.Category == RoleCategoryHR {
				triggeredStatutes = append(triggeredStatutes, ProtectionIllinoisAIVIA, ProtectionCaliforniaFEHA)
			}
		} else if riskTier == RiskTierCritical || riskTier == RiskTierHigh {
			triggeredStatutes = append(triggeredStatutes, ProtectionColoradoAIA)
		}

		mitigationStrategy := e.generateMitigationStrategy(riskTier, role.Category)

		assessment := RoleImpactAssessment{
			RoleID:                role.RoleID,
			Title:                 role.Title,
			Category:              role.Category,
			Department:            role.Department,
			Headcount:             role.Headcount,
			AutomationExposure:    exposure,
			RiskTier:              riskTier,
			EstimatedDisplacedFTE: displacedFTE,
			RecommendedRetrainHrs: retrainHrs,
			TriggeredStatutes:     triggeredStatutes,
			MitigationStrategy:    mitigationStrategy,
		}

		report.RoleAssessments = append(report.RoleAssessments, assessment)

		// Generate statutory Duty-of-Care notice if exposure is High or Critical
		if riskTier == RiskTierCritical || riskTier == RiskTierHigh || hasHighImpactDecisions {
			notice := DutyOfCareNotice{
				NoticeID:            fmt.Sprintf("not_%s", randHex(6)),
				Statute:             "CO SB 24-205 § 6-1-1703(1)(b) & NYC LL144 § 20-870",
				SystemName:          systemName,
				TargetRole:          role.Title,
				NoticeDate:          evaluatedAt,
				EffectiveDate:       evaluatedAt.AddDate(0, 0, 14), // 14 days pre-deployment notice
				NoticeSummary:       fmt.Sprintf("Statutory Notification: AI System '%s' introduces automated task assistance for %s. Enterprise duty-of-care, human-in-the-loop oversight, and retraining pathways are in effect.", systemName, role.Title),
				OptOutAvailable:     true,
				DisputeContactEmail: "workforce-governance@enterprise.internal",
			}
			notice.ComputeNoticeHash()
			report.DutyOfCareNotices = append(report.DutyOfCareNotices, notice)
		}

		// Department aggregation
		dept := role.Department
		if dept == "" {
			dept = string(role.Category)
		}
		if summary, ok := deptMap[dept]; !ok {
			deptMap[dept] = &DepartmentImpactSummary{
				Department:         dept,
				TotalHeadcount:     role.Headcount,
				AverageExposure:    exposure,
				HighestRiskTier:    riskTier,
				TotalDisplacedFTE:  displacedFTE,
				TotalRetrainingHrs: retrainHrs,
			}
		} else {
			summary.TotalHeadcount += role.Headcount
			summary.AverageExposure = (summary.AverageExposure + exposure) / 2.0
			summary.TotalDisplacedFTE += displacedFTE
			summary.TotalRetrainingHrs += retrainHrs
			if e.isHigherRisk(riskTier, summary.HighestRiskTier) {
				summary.HighestRiskTier = riskTier
			}
		}
	}

	report.TotalHeadcount = totalHeadcount
	if totalHeadcount > 0 {
		report.AggregateExposureScore = weightedExposureSum / float64(totalHeadcount)
	}
	report.AggregateDisplacedFTE = aggregateDisplacedFTE
	report.AggregateRetrainHours = aggregateRetrainHrs
	report.OverallRiskTier = e.classifyRiskTier(report.AggregateExposureScore)

	// Collect department summaries
	for _, summary := range deptMap {
		report.DepartmentSummaries = append(report.DepartmentSummaries, *summary)
	}
	sort.Slice(report.DepartmentSummaries, func(i, j int) bool {
		return report.DepartmentSummaries[i].AverageExposure > report.DepartmentSummaries[j].AverageExposure
	})

	// Statutory findings synthesis
	if hasHighImpactDecisions {
		report.StatutoryFindings = append(report.StatutoryFindings,
			"CRITICAL: System makes consequential employment decisions. Mandatory CO SB 24-205 risk assessment and NYC LL144 annual bias audit triggered.",
		)
	}
	if report.OverallRiskTier == RiskTierCritical || report.OverallRiskTier == RiskTierHigh {
		report.StatutoryFindings = append(report.StatutoryFindings,
			fmt.Sprintf("HIGH DISPLACEMENT RISK: %.1f estimated FTE displacement across workforce. Mandatory retraining and 14-day pre-deployment notice active.", aggregateDisplacedFTE),
		)
	} else {
		report.StatutoryFindings = append(report.StatutoryFindings,
			"LOW DISPLACEMENT IMPACT: AI system acts as augmentative task accelerator with minimal labor displacement.",
		)
	}

	report.ComputeReportChecksum()
	return report, nil
}

func (e *WorkforceEngine) classifyRiskTier(exposure float64) DisplacementRiskTier {
	switch {
	case exposure > 75.0:
		return RiskTierCritical
	case exposure > 50.0:
		return RiskTierHigh
	case exposure > 25.0:
		return RiskTierModerate
	default:
		return RiskTierLow
	}
}

func (e *WorkforceEngine) isHigherRisk(a, b DisplacementRiskTier) bool {
	rank := map[DisplacementRiskTier]int{
		RiskTierLow:      1,
		RiskTierModerate: 2,
		RiskTierHigh:     3,
		RiskTierCritical: 4,
	}
	return rank[a] > rank[b]
}

func (e *WorkforceEngine) generateMitigationStrategy(tier DisplacementRiskTier, cat RoleCategory) string {
	switch tier {
	case RiskTierCritical:
		return fmt.Sprintf("Mandatory workforce redeployment program; 120-hour upskilling in %s AI governance; strict human-in-the-loop approval gates on all automated actions.", cat)
	case RiskTierHigh:
		return fmt.Sprintf("60-hour structured retraining pathway; supervisory review requirement; quarterly algorithmic audit on job function drift in %s.", cat)
	case RiskTierModerate:
		return fmt.Sprintf("Augmentation enablement; 20-hour AI workflow optimization training for %s personnel.", cat)
	default:
		return "Standard operational AI usage guidelines; annual awareness training."
	}
}
