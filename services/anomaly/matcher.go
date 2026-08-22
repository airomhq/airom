package anomaly

import (
	"strings"
	"time"

	"github.com/airomhq/airom/internal/approved"
	"github.com/airomhq/airom/pkg/airom"
)

// EvaluateAnomalies evaluates diff against rules and manifest to find anomalies.
func EvaluateAnomalies(diff DiffReport, manifest *approved.Manifest) AnomalyReport {
	report := AnomalyReport{
		Diff:        diff,
		EvaluatedAt: time.Now(),
		Anomalies:   []Anomaly{},
	}

	highestSev := 0
	sevRank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	rankSev := map[int]string{1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

	addAnomaly := func(a Anomaly) {
		report.Anomalies = append(report.Anomalies, a)
		if sevRank[a.Severity] > highestSev {
			highestSev = sevRank[a.Severity]
		}
	}

	for _, c := range diff.Added {
		path := getPath(c)

		// shadow-ai (HIGH)
		if manifest != nil {
			isAppr, _, _ := manifest.IsApproved(c.PURL, path)
			if !isAppr {
				addAnomaly(Anomaly{
					ID:          "shadow-ai",
					Type:        "shadow-ai",
					Severity:    "HIGH",
					Component:   c.Name,
					Location:    path,
					Message:     "Added component not found in .airomapproved",
					Remediation: "Add to manifest or remove component",
				})
			}
		}

		checkProximity(c.Name, path, addAnomaly)
	}

	for _, m := range diff.Modified {
		// model-swap (HIGH)
		if m.OldProvider != m.NewProvider || (m.OldVersion != m.NewVersion && m.OldVersion != "") {
			addAnomaly(Anomaly{
				ID:          "model-swap",
				Type:        "model-swap",
				Severity:    "HIGH",
				Component:   m.ComponentID,
				Message:     "Component modified with different Model ID / Provider.",
				Remediation: "Verify model swap is intentional",
			})
		}

		// config-drift (MEDIUM)
		if manifest != nil && len(m.ParamDeltas) > 0 {
			params := make(map[string]string)
			for k, v := range m.ParamDeltas {
				params[k] = v.NewValue
			}
			isDrift, _, msg := manifest.CheckConfigDrift(m.PURL, params)
			if isDrift {
				addAnomaly(Anomaly{
					ID:          "config-drift",
					Type:        "config-drift",
					Severity:    "MEDIUM",
					Component:   m.ComponentID,
					Message:     msg,
					Remediation: "Revert parameter configuration to approved bounds",
				})
			}
		}
	}

	if highestSev > 0 {
		report.HighestSeverity = rankSev[highestSev]
	}
	report.Clean = len(report.Anomalies) == 0

	return report
}

func getPath(c airom.Component) string {
	if len(c.Evidence.Occurrences) > 0 {
		return c.Evidence.Occurrences[0].Location.Path
	}
	return ""
}

func checkProximity(name, path string, add func(Anomaly)) {
	pathLower := strings.ToLower(path)

	// proximity-hiring (HIGH)
	if matchesAny(pathLower, "hiring", "resume", "candidate", "applicant", "ats") {
		add(Anomaly{
			ID:          "proximity-hiring",
			Type:        "proximity-hiring",
			Severity:    "HIGH",
			Component:   name,
			Location:    path,
			Message:     "Component in path matching hiring/resume/candidate/applicant/ats",
			StatuteRef:  "NYC LL144",
			Remediation: "Ensure compliance with NYC LL144",
		})
	}

	// proximity-credit (HIGH)
	if matchesAny(pathLower, "credit", "lending", "underwriting", "loan") {
		add(Anomaly{
			ID:          "proximity-credit",
			Type:        "proximity-credit",
			Severity:    "HIGH",
			Component:   name,
			Location:    path,
			Message:     "Component in path matching credit/lending/underwriting/loan",
			StatuteRef:  "FCRA/ECOA",
			Remediation: "Ensure compliance with FCRA/ECOA",
		})
	}

	// proximity-healthcare (HIGH)
	if matchesAny(pathLower, "patient", "clinical", "ehr", "medical") {
		add(Anomaly{
			ID:          "proximity-healthcare",
			Type:        "proximity-healthcare",
			Severity:    "HIGH",
			Component:   name,
			Location:    path,
			Message:     "Component in path matching patient/clinical/ehr/medical",
			StatuteRef:  "HIPAA/CA AB 3030",
			Remediation: "Ensure compliance with HIPAA/CA AB 3030",
		})
	}
}

func matchesAny(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
