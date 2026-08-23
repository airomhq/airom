package regwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Jurisdiction represents the statutory authority governing an AI regulation.
type Jurisdiction string

const (
	JurisdictionColorado   Jurisdiction = "CO-AG"        // Colorado Attorney General (CO SB 24-205)
	JurisdictionCalifornia Jurisdiction = "CA-CPPA"      // California Privacy Protection Agency (CA AB 2013, ADMT)
	JurisdictionNYC        Jurisdiction = "NYC-DCWP"     // NYC Dept. of Consumer and Worker Protection (Local Law 144)
	JurisdictionEU         Jurisdiction = "EU-AI-OFFICE" // EU AI Office (Regulation (EU) 2024/1689)
	JurisdictionUSFederal  Jurisdiction = "US-FTC-EEOC"  // FTC & EEOC Federal AI Guidance
	JurisdictionIllinois   Jurisdiction = "IL-BIPA"      // Illinois Biometric Information Privacy Act
	JurisdictionTexas      Jurisdiction = "TX-TRAIGA"    // Texas Responsible AI Governance Act
	JurisdictionVirginia   Jurisdiction = "VA-VCDPA"     // Virginia Consumer Data Protection Act
)

// DeltaSeverity indicates the governance impact of a statutory modification.
type DeltaSeverity string

const (
	SeverityBreaking       DeltaSeverity = "BREAKING"       // New mandatory obligations or audit requirements
	SeverityClarification  DeltaSeverity = "CLARIFICATION"  // Updated statutory guidance, definitions, or thresholds
	SeverityAdministrative DeltaSeverity = "ADMINISTRATIVE" // Timeline adjustments or procedural notices
)

// StatuteSection represents a single clause or article in a legislative document.
type StatuteSection struct {
	ID          string `json:"id"`           // e.g. "6-1-1703(1)(a)" or "Article-50"
	Title       string `json:"title"`        // e.g. "Risk Management Policy"
	Content     string `json:"content"`      // Full legal text
	SectionHash string `json:"section_hash"` // SHA-256 hash of cleaned text
}

// ComputeHash calculates deterministic SHA-256 over section text.
func (s *StatuteSection) ComputeHash() string {
	cleaned := strings.TrimSpace(s.Content)
	sum := sha256.Sum256([]byte(cleaned))
	s.SectionHash = hex.EncodeToString(sum[:])
	return s.SectionHash
}

// StatutoryDocument represents an official state or global AI regulation document.
type StatutoryDocument struct {
	Jurisdiction  Jurisdiction     `json:"jurisdiction"`
	Title         string           `json:"title"`
	SourceURL     string           `json:"source_url"`
	Version       string           `json:"version"`
	EffectiveDate time.Time        `json:"effective_date"`
	LastScraped   time.Time        `json:"last_scraped"`
	DocumentHash  string           `json:"document_hash"`
	Sections      []StatuteSection `json:"sections"`
}

// ComputeHash calculates deterministic SHA-256 over all constituent sections.
func (d *StatutoryDocument) ComputeHash() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s|%s|%s\n", d.Jurisdiction, d.Title, d.Version))
	for i := range d.Sections {
		b.WriteString(fmt.Sprintf("%s:%s\n", d.Sections[i].ID, d.Sections[i].ComputeHash()))
	}
	sum := sha256.Sum256([]byte(b.String()))
	d.DocumentHash = hex.EncodeToString(sum[:])
	return d.DocumentHash
}

// SectionDelta records a specific difference between two statutory section revisions.
type SectionDelta struct {
	SectionID      string        `json:"section_id"`
	ChangeType     string        `json:"change_type"` // "ADDED", "REMOVED", "MODIFIED", "UNCHANGED"
	Severity       DeltaSeverity `json:"severity"`
	OldContent     string        `json:"old_content,omitempty"`
	NewContent     string        `json:"new_content,omitempty"`
	DiffSummary    string        `json:"diff_summary"`
	ImpactedChecks []string      `json:"impacted_checks"`
}

// StatutoryDiff represents the comprehensive semantic delta between two document versions.
type StatutoryDiff struct {
	Jurisdiction      Jurisdiction   `json:"jurisdiction"`
	OldVersion        string         `json:"old_version"`
	NewVersion        string         `json:"new_version"`
	Timestamp         time.Time      `json:"timestamp"`
	HasChanges        bool           `json:"has_changes"`
	MaxSeverity       DeltaSeverity  `json:"max_severity"`
	SectionDeltas     []SectionDelta `json:"section_deltas"`
	Summary           string         `json:"summary"`
	ImpactedRulepacks []string       `json:"impacted_rulepacks"`
}

// RegulatoryAlert represents a real-time notification generated when statutory feeds update.
type RegulatoryAlert struct {
	ID                string        `json:"id"`
	Jurisdiction      Jurisdiction  `json:"jurisdiction"`
	Title             string        `json:"title"`
	Severity          DeltaSeverity `json:"severity"`
	EffectiveDate     time.Time     `json:"effective_date"`
	Summary           string        `json:"summary"`
	ImpactedRulepacks []string      `json:"impacted_rulepacks"`
	ActionRequired    string        `json:"action_required"`
	CreatedAt         time.Time     `json:"created_at"`
}
