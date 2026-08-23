package workforce

import (
	"fmt"
	"strings"
	"time"
)

// RenderWorkforceDashboard generates a comprehensive ASCII terminal dashboard of the workforce impact assessment.
func RenderWorkforceDashboard(report *WorkforceAssessmentReport) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "  AIROM AI WORKFORCE IMPACT & JOB DISPLACEMENT RISK DASHBOARD\n")
	fmt.Fprintf(&sb, "  Organization: %s | System: %s | Evaluated: %s\n",
		report.OrganizationID, report.SystemName, report.EvaluatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "  Total Headcount: %d | Aggregate Exposure: %.1f%% | Displaced FTE: %.1f | Retraining: %d hrs\n",
		report.TotalHeadcount, report.AggregateExposureScore, report.AggregateDisplacedFTE, report.AggregateRetrainHours)
	fmt.Fprintf(&sb, "  Overall Displacement Risk Tier: [%s]\n", report.OverallRiskTier)
	fmt.Fprintf(&sb, "====================================================================================================\n")

	// Department Heatmap Table
	fmt.Fprintf(&sb, "\n--- DEPARTMENT DISPLACEMENT RISK HEATMAP ---\n")
	fmt.Fprintf(&sb, "%-24s | %-10s | %-12s | %-14s | %-14s | %-12s\n",
		"DEPARTMENT", "HEADCOUNT", "AVG EXPOSURE", "MAX RISK TIER", "DISPLACED FTE", "RETRAIN HRS")
	fmt.Fprintf(&sb, "-------------------------+------------+--------------+----------------+----------------+-------------\n")
	for _, dept := range report.DepartmentSummaries {
		fmt.Fprintf(&sb, "%-24s | %-10d | %-11.1f%% | %-14s | %-14.1f | %-12d\n",
			dept.Department, dept.TotalHeadcount, dept.AverageExposure, dept.HighestRiskTier, dept.TotalDisplacedFTE, dept.TotalRetrainingHrs)
	}

	// Role Impact Table
	fmt.Fprintf(&sb, "\n--- ROLE-LEVEL AUTOMATION EXPOSURE MATRIX ---\n")
	fmt.Fprintf(&sb, "%-24s | %-20s | %-6s | %-10s | %-10s | %-12s | %-10s\n",
		"ROLE TITLE", "CATEGORY", "HEAD", "EXPOSURE", "RISK TIER", "DISPL. FTE", "RETRAIN")
	fmt.Fprintf(&sb, "-------------------------+----------------------+--------+------------+------------+--------------+-----------\n")
	for _, role := range report.RoleAssessments {
		fmt.Fprintf(&sb, "%-24s | %-20s | %-6d | %-9.1f%% | %-10s | %-12.1f | %-10d\n",
			role.Title, role.Category, role.Headcount, role.AutomationExposure, role.RiskTier, role.EstimatedDisplacedFTE, role.RecommendedRetrainHrs)
	}

	// Statutory Findings & Duty of Care Notices
	fmt.Fprintf(&sb, "\n--- STATUTORY FINDINGS & DUTY-OF-CARE MANDATES (%d NOTICES) ---\n", len(report.DutyOfCareNotices))
	for _, finding := range report.StatutoryFindings {
		fmt.Fprintf(&sb, "  • %s\n", finding)
	}
	if len(report.DutyOfCareNotices) > 0 {
		fmt.Fprintf(&sb, "\n  [Active Duty-of-Care Employee Notices Generated]:\n")
		for i, notice := range report.DutyOfCareNotices {
			if i >= 5 {
				fmt.Fprintf(&sb, "  ... and %d more statutory notices.\n", len(report.DutyOfCareNotices)-5)
				break
			}
			fmt.Fprintf(&sb, "  [%s] Target Role: %s | Effective: %s | Opt-Out: %t | Statute: %s\n",
				notice.NoticeID, notice.TargetRole, notice.EffectiveDate.Format("2006-01-02"), notice.OptOutAvailable, notice.Statute)
		}
	}

	fmt.Fprintf(&sb, "====================================================================================================\n")
	return sb.String()
}
