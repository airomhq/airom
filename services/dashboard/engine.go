package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// DashboardEngine computes multi-organization rollups, executive posture KPIs, and grading matrices.
type DashboardEngine struct{}

// NewDashboardEngine constructs a new DashboardEngine instance.
func NewDashboardEngine() *DashboardEngine {
	return &DashboardEngine{}
}

// CalculateExecutivePosture aggregates organization rollups into a comprehensive executive posture matrix.
func (e *DashboardEngine) CalculateExecutivePosture(orgs []OrganizationRollup) (*MultiOrgPostureMatrix, error) {
	now := time.Now().UTC()

	matrix := &MultiOrgPostureMatrix{
		MatrixID:      fmt.Sprintf("mat_%s", randHex(6)),
		Organizations: make([]OrganizationRollup, len(orgs)),
		GeneratedAt:   now,
	}

	var (
		totalRepos        int
		totalComponents   int
		totalCriticalGaps int
		totalShadowAI     int
		totalDisplacedFTE float64
		totalUrgentFiling int
		weightedCompSum   float64
		totalWeight       float64
	)

	for i, org := range orgs {
		if org.TotalComponents <= 0 {
			org.TotalComponents = 1
		}

		// Calculate Posture Grade for the single org
		org.PostureGrade = e.computeGrade(org.ComplianceScore, org.CriticalGapsCount, org.UrgentFilingsCount)

		totalRepos += org.RepositoryCount
		totalComponents += org.TotalComponents
		totalCriticalGaps += org.CriticalGapsCount
		totalShadowAI += org.ShadowAICount
		totalDisplacedFTE += org.DisplacedFTECount
		totalUrgentFiling += org.UrgentFilingsCount

		weight := float64(org.TotalComponents)
		weightedCompSum += org.ComplianceScore * weight
		totalWeight += weight

		matrix.Organizations[i] = org
	}

	// Sort organizations descending by critical gaps, then ascending by compliance score
	sort.Slice(matrix.Organizations, func(i, j int) bool {
		if matrix.Organizations[i].CriticalGapsCount != matrix.Organizations[j].CriticalGapsCount {
			return matrix.Organizations[i].CriticalGapsCount > matrix.Organizations[j].CriticalGapsCount
		}
		return matrix.Organizations[i].ComplianceScore < matrix.Organizations[j].ComplianceScore
	})

	var aggregateCompliance float64
	if totalWeight > 0 {
		aggregateCompliance = weightedCompSum / totalWeight
	}

	overallGrade := e.computeGrade(aggregateCompliance, totalCriticalGaps, totalUrgentFiling)

	matrix.Summary = ExecutivePostureSummary{
		TotalOrganizations:  len(orgs),
		TotalRepositories:   totalRepos,
		TotalAIComponents:   totalComponents,
		AggregateCompliance: aggregateCompliance,
		OverallPostureGrade: overallGrade,
		TotalCriticalGaps:   totalCriticalGaps,
		TotalShadowAITools:  totalShadowAI,
		TotalDisplacedFTE:   totalDisplacedFTE,
		TotalUrgentFilings:  totalUrgentFiling,
		EvaluatedAt:         now,
	}

	matrix.ComputeMatrixChecksum()
	return matrix, nil
}

func (e *DashboardEngine) computeGrade(compliance float64, criticalGaps, urgentFilings int) PostureGrade {
	switch {
	case compliance >= 95.0 && criticalGaps == 0 && urgentFilings == 0:
		return GradeAPlus
	case compliance >= 90.0 && criticalGaps == 0:
		return GradeA
	case compliance >= 80.0 && criticalGaps <= 2:
		return GradeB
	case compliance >= 65.0 && criticalGaps <= 5:
		return GradeC
	default:
		return GradeF
	}
}

// RenderExecutiveDashboard formats a comprehensive executive terminal dashboard.
func RenderExecutiveDashboard(m *MultiOrgPostureMatrix) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "  AIROM ENTERPRISE COMPLIANCE & AI GOVERNANCE EXECUTIVE DASHBOARD\n")
	fmt.Fprintf(&sb, "  Evaluated: %s | Matrix ID: %s | Overall Posture Grade: [%s]\n",
		m.GeneratedAt.UTC().Format(time.RFC3339), m.MatrixID, m.Summary.OverallPostureGrade)
	fmt.Fprintf(&sb, "  Orgs: %d | Repos: %d | AI Components: %d | Aggregate Compliance: %.1f%%\n",
		m.Summary.TotalOrganizations, m.Summary.TotalRepositories, m.Summary.TotalAIComponents, m.Summary.AggregateCompliance)
	fmt.Fprintf(&sb, "  Critical Gaps: %d | Shadow AI Tools: %d | Displaced FTE: %.1f | Urgent Filings: %d\n",
		m.Summary.TotalCriticalGaps, m.Summary.TotalShadowAITools, m.Summary.TotalDisplacedFTE, m.Summary.TotalUrgentFilings)
	fmt.Fprintf(&sb, "====================================================================================================\n\n")

	fmt.Fprintf(&sb, "%-22s | %-14s | %-6s | %-10s | %-6s | %-10s | %-8s | %-10s\n",
		"ORGANIZATION", "SECTOR", "REPOS", "COMPLIANCE", "GRADE", "CRIT. GAPS", "SHADOW", "URGENT DUE")
	fmt.Fprintf(&sb, "-----------------------+----------------+--------+------------+--------+------------+----------+------------\n")

	for _, org := range m.Organizations {
		name := org.OrganizationName
		if len(name) > 22 {
			name = name[:19] + "..."
		}
		fmt.Fprintf(&sb, "%-22s | %-14s | %-6d | %-9.1f%% | %-6s | %-10d | %-8d | %-10d\n",
			name, org.Sector, org.RepositoryCount, org.ComplianceScore, org.PostureGrade,
			org.CriticalGapsCount, org.ShadowAICount, org.UrgentFilingsCount)
	}

	fmt.Fprintf(&sb, "\n--- CROSS-JURISDICTION COMPLIANCE POSTURE BREAKDOWN ---\n")
	frameworkTotals := make(map[string]float64)
	frameworkCounts := make(map[string]int)

	for _, org := range m.Organizations {
		for fw, score := range org.FrameworkCompliance {
			frameworkTotals[fw] += score
			frameworkCounts[fw]++
		}
	}

	for fw, total := range frameworkTotals {
		avg := total / float64(frameworkCounts[fw])
		status := "COMPLIANT"
		if avg < 80.0 {
			status = "ACTION REQUIRED"
		}
		fmt.Fprintf(&sb, "  • %-20s: %5.1f%% [%s]\n", fw, avg, status)
	}

	fmt.Fprintf(&sb, "====================================================================================================\n")
	return sb.String()
}
