package workforce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// RoleCategory categorizes enterprise functional domains.
type RoleCategory string

const (
	RoleCategoryEngineering RoleCategory = "ENGINEERING"
	RoleCategoryCustomerOps RoleCategory = "CUSTOMER_OPERATIONS"
	RoleCategorySalesMktg   RoleCategory = "SALES_MARKETING"
	RoleCategoryFinance     RoleCategory = "FINANCE_ACCOUNTING"
	RoleCategoryLegal       RoleCategory = "LEGAL_COMPLIANCE"
	RoleCategoryHR          RoleCategory = "HUMAN_RESOURCES"
	RoleCategoryGeneralOps  RoleCategory = "GENERAL_OPERATIONS"
	RoleCategoryCreative    RoleCategory = "CREATIVE_CONTENT"
)

// DisplacementRiskTier classifies the severity of job displacement or automation exposure.
type DisplacementRiskTier string

const (
	RiskTierLow      DisplacementRiskTier = "LOW"      // 0% - 25% task automation exposure
	RiskTierModerate DisplacementRiskTier = "MODERATE" // 26% - 50% task automation exposure
	RiskTierHigh     DisplacementRiskTier = "HIGH"     // 51% - 75% task automation exposure
	RiskTierCritical DisplacementRiskTier = "CRITICAL" // 76% - 100% task automation exposure
)

// StatutoryProtection flags specific employment labor regulations triggered by the system.
type StatutoryProtection string

const (
	ProtectionColoradoAIA    StatutoryProtection = "CO-SB-24-205-SEC-6-1-1703" // Colorado Duty of Reasonable Care
	ProtectionNYCAEDT        StatutoryProtection = "NYC-LL144-DCWP-20-870"     // NYC Automated Employment Decision Tool
	ProtectionIllinoisAIVIA  StatutoryProtection = "IL-820-ILCS-42"            // Illinois AI Video Interview Act
	ProtectionCaliforniaFEHA StatutoryProtection = "CA-FEHA-ADMT-SEC-11003"    // California Automated Decision Systems
	ProtectionEUAIAArticle6  StatutoryProtection = "EU-AIA-ANNEX-III-4"        // EU AI Act High-Risk Employment
)

// AISystemCapability represents functional abilities of an evaluated AI system.
type AISystemCapability struct {
	Name                string   `json:"name"`                  // e.g. "code-generation", "customer-dialogue", "resume-screening"
	AutomatedTasks      []string `json:"automated_tasks"`       // Specific task definitions
	AutonomyLevel       float64  `json:"autonomy_level"`        // 0.0 (assisted) to 1.0 (fully autonomous)
	HighImpactDecisions bool     `json:"high_impact_decisions"` // Adverse employment consequential decisions
}

// RoleProfile models an enterprise job classification evaluated for automation exposure.
type RoleProfile struct {
	RoleID          string       `json:"role_id"`
	Title           string       `json:"title"`
	Category        RoleCategory `json:"category"`
	Department      string       `json:"department"`
	Headcount       int          `json:"headcount"`
	CoreTasks       []string     `json:"core_tasks"`
	MedianSalaryUSD float64      `json:"median_salary_usd"`
}

// RoleImpactAssessment captures the calculated impact of AI deployment on a single role.
type RoleImpactAssessment struct {
	RoleID                string                `json:"role_id"`
	Title                 string                `json:"title"`
	Category              RoleCategory          `json:"category"`
	Department            string                `json:"department"`
	Headcount             int                   `json:"headcount"`
	AutomationExposure    float64               `json:"automation_exposure"` // 0.0 - 100.0%
	RiskTier              DisplacementRiskTier  `json:"risk_tier"`
	EstimatedDisplacedFTE float64               `json:"estimated_displaced_fte"`
	RecommendedRetrainHrs int                   `json:"recommended_retraining_hours"`
	TriggeredStatutes     []StatutoryProtection `json:"triggered_statutes"`
	MitigationStrategy    string                `json:"mitigation_strategy"`
}

// DepartmentImpactSummary aggregates workforce metrics by enterprise department.
type DepartmentImpactSummary struct {
	Department         string               `json:"department"`
	TotalHeadcount     int                  `json:"total_headcount"`
	AverageExposure    float64              `json:"average_exposure"`
	HighestRiskTier    DisplacementRiskTier `json:"highest_risk_tier"`
	TotalDisplacedFTE  float64              `json:"total_displaced_fte"`
	TotalRetrainingHrs int                  `json:"total_retraining_hours"`
}

// DutyOfCareNotice represents a statutory pre-deployment notification for impacted workforce members.
type DutyOfCareNotice struct {
	NoticeID            string    `json:"notice_id"`
	Statute             string    `json:"statute"`
	SystemName          string    `json:"system_name"`
	TargetRole          string    `json:"target_role"`
	NoticeDate          time.Time `json:"notice_date"`
	EffectiveDate       time.Time `json:"effective_date"`
	NoticeSummary       string    `json:"notice_summary"`
	OptOutAvailable     bool      `json:"opt_out_available"`
	DisputeContactEmail string    `json:"dispute_contact_email"`
	NoticeHash          string    `json:"notice_hash"`
}

// ComputeNoticeHash generates a SHA-256 integrity hash for the statutory notice.
func (n *DutyOfCareNotice) ComputeNoticeHash() string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%t",
		n.NoticeID, n.Statute, n.SystemName, n.TargetRole, n.NoticeDate.UTC().Format(time.RFC3339), n.OptOutAvailable)
	sum := sha256.Sum256([]byte(raw))
	n.NoticeHash = hex.EncodeToString(sum[:])
	return n.NoticeHash
}

// WorkforceAssessmentReport is the comprehensive statutory workforce impact artifact.
type WorkforceAssessmentReport struct {
	ReportID               string                    `json:"report_id"`
	OrganizationID         string                    `json:"organization_id"`
	SystemName             string                    `json:"system_name"`
	EvaluatedAt            time.Time                 `json:"evaluated_at"`
	TotalHeadcount         int                       `json:"total_headcount"`
	AggregateExposureScore float64                   `json:"aggregate_exposure_score"` // 0.0 - 100.0%
	AggregateDisplacedFTE  float64                   `json:"aggregate_displaced_fte"`
	AggregateRetrainHours  int                       `json:"aggregate_retraining_hours"`
	OverallRiskTier        DisplacementRiskTier      `json:"overall_risk_tier"`
	RoleAssessments        []RoleImpactAssessment    `json:"role_assessments"`
	DepartmentSummaries    []DepartmentImpactSummary `json:"department_summaries"`
	DutyOfCareNotices      []DutyOfCareNotice        `json:"duty_of_care_notices"`
	StatutoryFindings      []string                  `json:"statutory_findings"`
	ReportChecksum         string                    `json:"report_checksum"`
}

// ComputeReportChecksum calculates a deterministic SHA-256 composite checksum for the report.
func (r *WorkforceAssessmentReport) ComputeReportChecksum() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s|%.2f|%.2f|%d|%s\n",
		r.ReportID, r.OrganizationID, r.SystemName, r.EvaluatedAt.UTC().Format(time.RFC3339),
		r.AggregateExposureScore, r.AggregateDisplacedFTE, r.AggregateRetrainHours, r.OverallRiskTier)
	for _, role := range r.RoleAssessments {
		_, _ = fmt.Fprintf(h, "%s:%.2f:%s:%.2f\n", role.RoleID, role.AutomationExposure, role.RiskTier, role.EstimatedDisplacedFTE)
	}
	r.ReportChecksum = hex.EncodeToString(h.Sum(nil))
	return r.ReportChecksum
}
