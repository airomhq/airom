package document

import (
	"time"

	"github.com/airomhq/airom/services/compliancedb"
	"github.com/airomhq/airom/services/report"
)

// ItemStatus represents the Green/Yellow/Red state of a compliance review item.
type ItemStatus string

const (
	StatusGreenVerified             ItemStatus = "GREEN_VERIFIED"
	StatusYellowAttestationRequired ItemStatus = "YELLOW_ATTESTATION_REQUIRED"
	StatusRedGap                    ItemStatus = "RED_GAP"
)

// ReviewItem represents a single line item in the human review gateway.
type ReviewItem struct {
	ID                      string     `json:"id"`
	Category                string     `json:"category"` // e.g. "System Identity", "Consumer Notice", "Bias Audit"
	Title                   string     `json:"title"`
	Description             string     `json:"description"`
	Status                  ItemStatus `json:"status"`
	StatuteRef              string     `json:"statute_ref,omitempty"`
	EvidenceCitation        string     `json:"evidence_citation,omitempty"`
	IsLocked                bool       `json:"is_locked"`         // Green items are locked
	Value                   string     `json:"value,omitempty"`   // User answer for Yellow
	Options                 []string   `json:"options,omitempty"` // Dropdown choices for Yellow
	IsAnswered              bool       `json:"is_answered"`
	RequiresAcknowledgement bool       `json:"requires_acknowledgement"` // For Red gaps
	IsAcknowledged          bool       `json:"is_acknowledged"`
	AcknowledgementReason   string     `json:"acknowledgement_reason,omitempty"`
}

// DocumentPackage is a regulator-ready compliance packet managed by the Human Review Gateway.
type DocumentPackage struct {
	ID              string                   `json:"id"`
	OrgID           string                   `json:"org_id"`
	RepoID          string                   `json:"repo_id"`
	Framework       string                   `json:"framework"` // colorado-ai-act, nyc-ll144, ca-ab2013
	Title           string                   `json:"title"`
	CommitSHA       string                   `json:"commit_sha"`
	CreatedAt       time.Time                `json:"created_at"`
	IsCertified     bool                     `json:"is_certified"`
	CertifiedBy     string                   `json:"certified_by,omitempty"`
	CertifiedEmail  string                   `json:"certified_email,omitempty"`
	CertifiedTitle  string                   `json:"certified_title,omitempty"`
	CertifiedAt     *time.Time               `json:"certified_at,omitempty"`
	Items           []ReviewItem             `json:"items"`
	Report          *report.ComplianceReport `json:"report,omitempty"`
	HTMLPayload     string                   `json:"html_payload,omitempty"`
	MarkdownPayload string                   `json:"markdown_payload,omitempty"`
	AIBOMSHA256     string                   `json:"aibom_sha256"`
	AuditEntryID    string                   `json:"audit_entry_id,omitempty"`
	Metadata        map[string]string        `json:"metadata,omitempty"`
}

// IsReadyToCertify checks if all Yellow items are answered and all Red items are acknowledged.
func (p *DocumentPackage) IsReadyToCertify() (bool, []string) {
	var blockers []string

	for _, item := range p.Items {
		switch item.Status {
		case StatusYellowAttestationRequired:
			if !item.IsAnswered || item.Value == "" {
				blockers = append(blockers, "Unanswered Yellow item: "+item.Title)
			}
		case StatusRedGap:
			if item.RequiresAcknowledgement && !item.IsAcknowledged {
				blockers = append(blockers, "Unacknowledged Red gap: "+item.Title)
			}
		}
	}

	return len(blockers) == 0, blockers
}

// HumanToken represents an ephemeral, signed token for human-in-the-loop actions.
type HumanToken struct {
	TokenID    string    `json:"token_id"`
	UserID     string    `json:"user_id"`
	UserEmail  string    `json:"user_email"`
	DocumentID string    `json:"document_id"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// TokenRequest is the payload to request an ephemeral human token.
type TokenRequest struct {
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	DocumentID string `json:"document_id"`
}

// TokenResponse contains the issued human confirmation token.
type TokenResponse struct {
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
	TTLSeconds int       `json:"ttl_seconds"`
}

// CertifyRequest is the payload required to certify a document package.
type CertifyRequest struct {
	UserID                 string            `json:"user_id"`
	UserEmail              string            `json:"user_email"`
	UserTitle              string            `json:"user_title"`
	HumanConfirmationToken string            `json:"human_confirmation_token"`
	YellowAnswers          map[string]string `json:"yellow_answers,omitempty"`       // itemID -> answer
	RedAcknowledgements    map[string]string `json:"red_acknowledgements,omitempty"` // itemID -> reason
	SignatureText          string            `json:"signature_text"`
}

// FilingAuditEntry represents an immutable audit log record in filing_audit_log.
type FilingAuditEntry struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	RepoID        string    `json:"repo_id"`
	Framework     string    `json:"framework"`
	ActionType    string    `json:"action_type"` // e.g. "DOCUMENT_CERTIFIED", "PUBLIC_POSTING_GENERATED"
	DocumentID    string    `json:"document_id"`
	AIBOMSHA256   string    `json:"aibom_sha256"`
	ActorUserID   string    `json:"actor_user_id"`
	ActorEmail    string    `json:"actor_email"`
	HumanTokenID  string    `json:"human_token_id"`
	Timestamp     time.Time `json:"timestamp"`
	SignatureHash string    `json:"signature_hash"`
	Metadata      string    `json:"metadata,omitempty"`
}

// CreatePackageRequest is the payload to compile a document package.
type CreatePackageRequest struct {
	OrgID         string                           `json:"org_id"`
	OrgName       string                           `json:"org_name"`
	RepoID        string                           `json:"repo_id"`
	RepoName      string                           `json:"repo_name"`
	CommitSHA     string                           `json:"commit_sha"`
	Framework     string                           `json:"framework"` // colorado-ai-act, nyc-ll144, ca-ab2013
	AIBOMSHA256   string                           `json:"aibom_sha256"`
	Evaluations   []compliancedb.ControlEvaluation `json:"evaluations,omitempty"`
	EvidenceIndex map[string]report.EvidenceRef    `json:"evidence_index,omitempty"`
	SignerName    string                           `json:"signer_name,omitempty"`
	SignerTitle   string                           `json:"signer_title,omitempty"`
}
