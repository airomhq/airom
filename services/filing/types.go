package filing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Jurisdiction represents the statutory body for automated filing and renewals.
type Jurisdiction string

const (
	JurisdictionColorado   Jurisdiction = "CO-AG"        // Colorado Attorney General (CO SB 24-205)
	JurisdictionCalifornia Jurisdiction = "CA-CPPA"      // California Privacy Protection Agency (CA AB 2013)
	JurisdictionNYC        Jurisdiction = "NYC-DCWP"     // NYC Dept. of Consumer & Worker Protection (LL144)
	JurisdictionEU         Jurisdiction = "EU-AI-OFFICE" // EU AI Office (Regulation (EU) 2024/1689)
	JurisdictionIllinois   Jurisdiction = "IL-BIPA"      // Illinois Biometric Information Privacy Act
	JurisdictionTexas      Jurisdiction = "TX-TRAIGA"    // Texas Responsible AI Governance Act
	JurisdictionVirginia   Jurisdiction = "VA-VCDPA"     // Virginia Consumer Data Protection Act
)

// FilingStatus indicates the lifecycle stage of a statutory filing package.
type FilingStatus string

const (
	StatusDraft            FilingStatus = "DRAFT"
	StatusVerified         FilingStatus = "VERIFIED"
	StatusSubmitted        FilingStatus = "SUBMITTED"
	StatusAcknowledged     FilingStatus = "ACKNOWLEDGED"
	StatusRejected         FilingStatus = "REJECTED"
	StatusRenewalRequired  FilingStatus = "RENEWAL_REQUIRED"
)

// RenewalUrgency indicates the statutory timeline urgency for upcoming renewals.
type RenewalUrgency string

const (
	UrgencyCurrent     RenewalUrgency = "CURRENT"      // > 90 days remaining
	UrgencyUpcoming90D RenewalUrgency = "UPCOMING_90D" // 61-90 days remaining
	UrgencyUpcoming30D RenewalUrgency = "UPCOMING_30D" // 15-60 days remaining
	UrgencyUpcoming14D RenewalUrgency = "UPCOMING_14D" // 8-14 days remaining
	UrgencyUpcoming7D  RenewalUrgency = "UPCOMING_7D"  // 2-7 days remaining
	UrgencyUrgent1D    RenewalUrgency = "URGENT_1D"    // <= 1 day remaining
	UrgencyOverdue     RenewalUrgency = "OVERDUE"      // Past statutory deadline
)

// SignerAttestation records officer attestation and cryptographic verification.
type SignerAttestation struct {
	OfficerName      string    `json:"officer_name"`
	OfficerTitle     string    `json:"officer_title"`
	OfficerEmail     string    `json:"officer_email"`
	OrganizationName string    `json:"organization_name"`
	SignedAt         time.Time `json:"signed_at"`
	SignatureHash    string    `json:"signature_hash"`
	AttestationText  string    `json:"attestation_text"`
}

// ComputeSignature generates a deterministic SHA-256 signature hash for the attestation.
func (s *SignerAttestation) ComputeSignature() string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		s.OfficerName, s.OfficerTitle, s.OfficerEmail, s.OrganizationName,
		s.SignedAt.UTC().Format(time.RFC3339), s.AttestationText)
	sum := sha256.Sum256([]byte(raw))
	s.SignatureHash = hex.EncodeToString(sum[:])
	return s.SignatureHash
}

// FilingArtifact represents a single document or structured data file within a filing package.
type FilingArtifact struct {
	RelativePath string `json:"relative_path"`
	ContentType  string `json:"content_type"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	Content      []byte `json:"-"` // Binary/text payload in memory
}

// ComputeChecksum calculates and sets the SHA-256 and byte size for an artifact.
func (a *FilingArtifact) ComputeChecksum() string {
	sum := sha256.Sum256(a.Content)
	a.SHA256 = hex.EncodeToString(sum[:])
	a.SizeBytes = int64(len(a.Content))
	return a.SHA256
}

// FilingManifest provides cryptographic integrity tracking for the entire filing package.
type FilingManifest struct {
	PackageID          string            `json:"package_id"`
	Jurisdiction       Jurisdiction      `json:"jurisdiction"`
	OrganizationID     string            `json:"organization_id"`
	RepositoryID       string            `json:"repository_id"`
	SnapshotID         string            `json:"snapshot_id"`
	StatutoryReference string            `json:"statutory_reference"`
	CreatedAt          time.Time         `json:"created_at"`
	PackageChecksum    string            `json:"package_checksum"`
	Signer             SignerAttestation `json:"signer"`
	Artifacts          []FilingArtifact  `json:"artifacts"`
}

// ComputePackageChecksum computes a deterministic composite hash over all constituent artifacts.
func (m *FilingManifest) ComputePackageChecksum() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%s|%s\n", m.PackageID, m.Jurisdiction, m.OrganizationID, m.RepositoryID, m.StatutoryReference)
	for _, art := range m.Artifacts {
		_, _ = fmt.Fprintf(h, "%s:%s:%d\n", art.RelativePath, art.SHA256, art.SizeBytes)
	}
	m.PackageChecksum = hex.EncodeToString(h.Sum(nil))
	return m.PackageChecksum
}

// FilingReceipt represents an immutable proof of statutory filing transmission and acknowledgment.
type FilingReceipt struct {
	ReceiptID          string       `json:"receipt_id"`
	PackageID          string       `json:"package_id"`
	Jurisdiction       Jurisdiction `json:"jurisdiction"`
	OrganizationID     string       `json:"organization_id"`
	SubmittedAt        time.Time    `json:"submitted_at"`
	PortalEndpoint     string       `json:"portal_endpoint"`
	Status             FilingStatus `json:"status"`
	AcknowledgmentToken string      `json:"acknowledgment_token"`
	SubmissionHash     string       `json:"submission_hash"`
	Message            string       `json:"message"`
}

// RenewalScheduleItem tracks statutory deadlines and recurring audit schedules for a single jurisdiction.
type RenewalScheduleItem struct {
	Jurisdiction       Jurisdiction   `json:"jurisdiction"`
	StatutoryMandate   string         `json:"statutory_mandate"`
	CycleDurationDays  int            `json:"cycle_duration_days"`
	LastFilingDate     *time.Time     `json:"last_filing_date,omitempty"`
	NextDeadlineDate   time.Time      `json:"next_deadline_date"`
	DaysRemaining      int            `json:"days_remaining"`
	Urgency            RenewalUrgency `json:"urgency"`
	RequiredAction     string         `json:"required_action"`
	AutoFilingEligible bool           `json:"auto_filing_eligible"`
	SubstantialModDate *time.Time     `json:"substantial_modification_date,omitempty"`
}

// RenewalCalendar aggregates the full compliance renewal landscape for an organization.
type RenewalCalendar struct {
	OrganizationID string                `json:"organization_id"`
	GeneratedAt    time.Time             `json:"generated_at"`
	Items          []RenewalScheduleItem `json:"items"`
	OverdueCount   int                   `json:"overdue_count"`
	UrgentCount    int                   `json:"urgent_count"`
	UpcomingCount  int                   `json:"upcoming_count"`
	CurrentCount   int                   `json:"current_count"`
}
