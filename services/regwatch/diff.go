package regwatch

import (
	"fmt"
	"strings"
	"time"
)

// DiffEngine computes semantic deltas across statutory revisions.
type DiffEngine struct {
	// Jurisdiction to rulepack mapping
	rulepackMap map[Jurisdiction][]string
}

// NewDiffEngine initializes a statutory diff engine.
func NewDiffEngine() *DiffEngine {
	return &DiffEngine{
		rulepackMap: map[Jurisdiction][]string{
			JurisdictionColorado:   {"rules/compliance/co-sb-24-205.yaml"},
			JurisdictionCalifornia: {"rules/compliance/ca-ab-2013.yaml"},
			JurisdictionNYC:        {"rules/compliance/nyc-ll144.yaml"},
			JurisdictionEU:         {"rules/compliance/eu-ai-act.yaml"},
			JurisdictionIllinois:   {"rules/compliance/il-bipa.yaml"},
			JurisdictionTexas:      {"rules/compliance/tx-traiga.yaml"},
			JurisdictionVirginia:   {"rules/compliance/va-vcdpa.yaml"},
			JurisdictionUSFederal:  {"rules/compliance/nist-ai-rmf.yaml"},
		},
	}
}

// ComputeDiff analyzes two statutory documents and produces a structured delta.
func (e *DiffEngine) ComputeDiff(oldDoc, newDoc StatutoryDocument) StatutoryDiff {
	oldSections := make(map[string]StatuteSection)
	for _, sec := range oldDoc.Sections {
		oldSections[sec.ID] = sec
	}

	newSections := make(map[string]StatuteSection)
	for _, sec := range newDoc.Sections {
		newSections[sec.ID] = sec
	}

	var deltas []SectionDelta
	maxSeverity := SeverityAdministrative
	hasChanges := false

	// Check for Added and Modified sections
	for _, newSec := range newDoc.Sections {
		oldSec, exists := oldSections[newSec.ID]
		if !exists {
			hasChanges = true
			sev := SeverityBreaking
			if isClarification(newSec.Content) {
				sev = SeverityClarification
			}
			if sev == SeverityBreaking {
				maxSeverity = SeverityBreaking
			} else if maxSeverity != SeverityBreaking {
				maxSeverity = SeverityClarification
			}

			deltas = append(deltas, SectionDelta{
				SectionID:      newSec.ID,
				ChangeType:     "ADDED",
				Severity:       sev,
				NewContent:     newSec.Content,
				DiffSummary:    fmt.Sprintf("Newly enacted statutory clause: %s (%s)", newSec.Title, newSec.ID),
				ImpactedChecks: deriveImpactedChecks(newDoc.Jurisdiction, newSec.ID),
			})
			continue
		}

		// Check if content hash changed
		if oldSec.ComputeHash() != newSec.ComputeHash() {
			hasChanges = true
			sev := classifyContentChange(oldSec.Content, newSec.Content)
			if sev == SeverityBreaking {
				maxSeverity = SeverityBreaking
			} else if sev == SeverityClarification && maxSeverity != SeverityBreaking {
				maxSeverity = SeverityClarification
			}

			deltas = append(deltas, SectionDelta{
				SectionID:      newSec.ID,
				ChangeType:     "MODIFIED",
				Severity:       sev,
				OldContent:     oldSec.Content,
				NewContent:     newSec.Content,
				DiffSummary:    fmt.Sprintf("Statutory clause modified: %s (%s)", newSec.Title, newSec.ID),
				ImpactedChecks: deriveImpactedChecks(newDoc.Jurisdiction, newSec.ID),
			})
		}
	}

	// Check for Removed sections
	for _, oldSec := range oldDoc.Sections {
		if _, exists := newSections[oldSec.ID]; !exists {
			hasChanges = true
			deltas = append(deltas, SectionDelta{
				SectionID:      oldSec.ID,
				ChangeType:     "REMOVED",
				Severity:       SeverityBreaking,
				OldContent:     oldSec.Content,
				DiffSummary:    fmt.Sprintf("Repealed or sunsetted statutory clause: %s (%s)", oldSec.Title, oldSec.ID),
				ImpactedChecks: deriveImpactedChecks(oldDoc.Jurisdiction, oldSec.ID),
			})
			maxSeverity = SeverityBreaking
		}
	}

	summary := "No statutory changes detected. Local governance rules are fully synchronized."
	if hasChanges {
		summary = fmt.Sprintf("Detected %d statutory section change(s) for %s [Impact: %s].",
			len(deltas), newDoc.Jurisdiction, maxSeverity)
	}

	impactedRulepacks := e.rulepackMap[newDoc.Jurisdiction]

	return StatutoryDiff{
		Jurisdiction:      newDoc.Jurisdiction,
		OldVersion:        oldDoc.Version,
		NewVersion:        newDoc.Version,
		Timestamp:         time.Now().UTC(),
		HasChanges:        hasChanges,
		MaxSeverity:       maxSeverity,
		SectionDeltas:     deltas,
		Summary:           summary,
		ImpactedRulepacks: impactedRulepacks,
	}
}

func isClarification(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "clarification") ||
		strings.Contains(lower, "technical guidance") ||
		strings.Contains(lower, "non-binding")
}

func classifyContentChange(oldContent, newContent string) DeltaSeverity {
	oldWords := strings.Fields(strings.ToLower(oldContent))
	newWords := strings.Fields(strings.ToLower(newContent))

	// Look for mandatory keywords introduced: "shall", "must", "required", "prohibited", "penalty"
	mandatoryTerms := []string{"shall", "must", "required", "prohibit", "mandatory", "audit", "fine", "penalty"}
	oldSet := make(map[string]bool)
	for _, w := range oldWords {
		oldSet[w] = true
	}

	for _, w := range newWords {
		if !oldSet[w] {
			for _, term := range mandatoryTerms {
				if strings.Contains(w, term) {
					return SeverityBreaking
				}
			}
		}
	}

	if len(newWords) > len(oldWords)*2 || len(oldWords) > len(newWords)*2 {
		return SeverityBreaking
	}

	return SeverityClarification
}

func deriveImpactedChecks(jurisdiction Jurisdiction, sectionID string) []string {
	prefix := string(jurisdiction)
	return []string{
		fmt.Sprintf("%s-RULE-%s", prefix, strings.ReplaceAll(sectionID, " ", "_")),
	}
}
