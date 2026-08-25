// Package pdf implements pure-Go publication-grade PDF generation
// for executive compliance scorecards and regulatory audit dossiers.
package pdf

import (
	"time"
)

// DocumentSpec defines the parameters for generating an executive compliance PDF dossier.
type DocumentSpec struct {
	Title             string            `json:"title"`
	OrganizationName  string            `json:"organizationName"`
	RepositoryName    string            `json:"repositoryName"`
	CommitSHA         string            `json:"commitSha"`
	FrameworkName     string            `json:"frameworkName"` // e.g. "EU AI Act Annex IV", "Colorado SB 24-205"
	ExecutiveSummary  string            `json:"executiveSummary"`
	ComplianceVerdict string            `json:"complianceVerdict"` // e.g. "CONFORMANT_WITH_EXCLUSIONS"
	TotalComponents   int               `json:"totalComponents"`
	GapsIdentified    int               `json:"gapsIdentified"`
	ControlsMet       int               `json:"controlsMet"`
	SignerName        string            `json:"signerName"`
	SignerTitle       string            `json:"signerTitle"`
	GeneratedAt       time.Time         `json:"generatedAt"`
	Sections          []DocumentSection `json:"sections"`
}

// DocumentSection represents a titled section of technical narrative in the PDF dossier.
type DocumentSection struct {
	Heading string `json:"heading"`
	Content string `json:"content"`
}

// PDFResult contains the rendered raw PDF byte stream and document metadata.
type PDFResult struct {
	DocumentID string    `json:"documentId"`
	SizeBytes  int       `json:"sizeBytes"`
	PageCount  int       `json:"pageCount"`
	PDFBytes   []byte    `json:"pdfBytes"`
	CreatedAt  time.Time `json:"createdAt"`
}
