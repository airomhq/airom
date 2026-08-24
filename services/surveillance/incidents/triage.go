package incidents

import (
	"time"
)

// TriageEngine automates statutory incident classification and regulatory dispatch preparation.
type TriageEngine struct{}

// NewTriageEngine constructs an incident triage engine.
func NewTriageEngine() *TriageEngine {
	return &TriageEngine{}
}

// TriageIncident computes mandatory deadlines and target regulatory authorities.
func (te *TriageEngine) TriageIncident(input AIIncidentInput) StatutoryDispatchPackage {
	occurred := input.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}

	pkg := StatutoryDispatchPackage{
		IncidentID: input.IncidentID,
		Severity:   input.Severity,
		TriagedAt:  time.Now().UTC(),
	}

	switch input.Severity {
	case SeverityDeathOrPhysicalHarm:
		pkg.NotificationWindow = "72_HOURS"
		pkg.MandatoryDeadline = occurred.Add(72 * time.Hour)
		pkg.TargetAuthorities = []string{
			"National Market Surveillance Authority (EU Member State)",
			"European AI Office (European Commission)",
			"US CPSC (Consumer Product Safety Commission)",
		}
		pkg.StatutoryDirectives = []string{
			"Regulation (EU) 2024/1689 (EU AI Act) Article 73(2) (Immediate 72-hour notice)",
			"NIST SP 1270 AI Risk Management Framework §3.4",
		}

	case SeverityCriticalInfraDisrupt, SeverityFundamentalRights:
		pkg.NotificationWindow = "15_DAYS"
		pkg.MandatoryDeadline = occurred.Add(15 * 24 * time.Hour)
		pkg.TargetAuthorities = []string{
			"National Market Surveillance Authority (EU Member State)",
			"European Data Protection Supervisor (EDPS)",
		}
		pkg.StatutoryDirectives = []string{
			"Regulation (EU) 2024/1689 (EU AI Act) Article 73(3) (15-day notice)",
		}

	case SeverityAlgorithmicBias:
		pkg.NotificationWindow = "90_DAYS"
		pkg.MandatoryDeadline = occurred.Add(90 * 24 * time.Hour)
		pkg.TargetAuthorities = []string{
			"Colorado Attorney General (Department of Law)",
			"US Equal Employment Opportunity Commission (EEOC)",
		}
		pkg.StatutoryDirectives = []string{
			"Colorado SB 24-205 § 6-1-1703 (Mandatory disclosure within 90 days of discovery)",
		}

	default:
		pkg.NotificationWindow = "15_DAYS"
		pkg.MandatoryDeadline = occurred.Add(15 * 24 * time.Hour)
		pkg.TargetAuthorities = []string{"National Market Surveillance Authority"}
		pkg.StatutoryDirectives = []string{"EU AI Act Article 73 General Incident Protocol"}
	}

	return pkg
}
