package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// PostureGrade represents an executive governance grade.
type PostureGrade string

const (
	GradeAPlus PostureGrade = "A+" // 95% - 100% compliance, 0 critical gaps, 0 overdue filings
	GradeA     PostureGrade = "A"  // 90% - 94% compliance, 0 critical gaps
	GradeB     PostureGrade = "B"  // 80% - 89% compliance, <= 2 critical gaps
	GradeC     PostureGrade = "C"  // 65% - 79% compliance, <= 5 critical gaps
	GradeF     PostureGrade = "F"  // < 65% compliance or > 5 critical gaps or overdue filings
)

// OrganizationRollup summarizes compliance and risk metrics for a single enterprise subsidiary or unit.
type OrganizationRollup struct {
	OrganizationID      string             `json:"organization_id"`
	OrganizationName    string             `json:"organization_name"`
	Sector              string             `json:"sector"`
	RepositoryCount     int                `json:"repository_count"`
	TotalComponents     int                `json:"total_components"`
	ComplianceScore     float64            `json:"compliance_score"` // 0.0 - 100.0%
	PostureGrade        PostureGrade       `json:"posture_grade"`
	CriticalGapsCount   int                `json:"critical_gaps_count"`
	ShadowAICount       int                `json:"shadow_ai_count"`
	DisplacedFTECount   float64            `json:"displaced_fte_count"`
	UrgentFilingsCount  int                `json:"urgent_filings_count"`
	FrameworkCompliance map[string]float64 `json:"framework_compliance"` // Key: Framework ID -> percentage
	LastAuditedAt       time.Time          `json:"last_audited_at"`
}

// ExecutivePostureSummary provides high-level executive KPIs across all enterprise organizations.
type ExecutivePostureSummary struct {
	TotalOrganizations  int          `json:"total_organizations"`
	TotalRepositories   int          `json:"total_repositories"`
	TotalAIComponents   int          `json:"total_ai_components"`
	AggregateCompliance float64      `json:"aggregate_compliance"` // 0.0 - 100.0%
	OverallPostureGrade PostureGrade `json:"overall_posture_grade"`
	TotalCriticalGaps   int          `json:"total_critical_gaps"`
	TotalShadowAITools  int          `json:"total_shadow_ai_tools"`
	TotalDisplacedFTE   float64      `json:"total_displaced_fte"`
	TotalUrgentFilings  int          `json:"total_urgent_filings"`
	EvaluatedAt         time.Time    `json:"evaluated_at"`
}

// MultiOrgPostureMatrix captures the full enterprise posture rollup.
type MultiOrgPostureMatrix struct {
	MatrixID       string                  `json:"matrix_id"`
	Summary        ExecutivePostureSummary `json:"summary"`
	Organizations  []OrganizationRollup    `json:"organizations"`
	GeneratedAt    time.Time               `json:"generated_at"`
	MatrixChecksum string                  `json:"matrix_checksum"`
}

// ComputeMatrixChecksum generates a composite SHA-256 integrity fingerprint for the posture matrix.
func (m *MultiOrgPostureMatrix) ComputeMatrixChecksum() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%d|%.2f|%s|%s\n",
		m.MatrixID, m.Summary.TotalOrganizations, m.Summary.AggregateCompliance,
		m.Summary.OverallPostureGrade, m.GeneratedAt.UTC().Format(time.RFC3339))
	for _, org := range m.Organizations {
		_, _ = fmt.Fprintf(h, "%s:%.2f:%s:%d:%d\n",
			org.OrganizationID, org.ComplianceScore, org.PostureGrade, org.CriticalGapsCount, org.ShadowAICount)
	}
	m.MatrixChecksum = hex.EncodeToString(h.Sum(nil))
	return m.MatrixChecksum
}
