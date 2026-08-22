package document

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/airomhq/airom/services/compliancedb"
	"github.com/airomhq/airom/services/report"
)

// Agent manages compliance document packages and human review gateways.
type Agent struct {
	mu        sync.RWMutex
	secret    []byte
	packages  map[string]*DocumentPackage
	auditLogs []FilingAuditEntry
}

// NewAgent instantiates a new ComplianceDocumentAgent.
func NewAgent(secret []byte) *Agent {
	if len(secret) == 0 {
		secret = []byte("airom-default-gateway-secret-key-32b")
	}
	return &Agent{
		secret:    secret,
		packages:  make(map[string]*DocumentPackage),
		auditLogs: make([]FilingAuditEntry, 0),
	}
}

// CreatePackage compiles a new compliance document package with Green/Yellow/Red categorizations.
func (a *Agent) CreatePackage(req CreatePackageRequest) (*DocumentPackage, error) {
	if req.RepoID == "" {
		return nil, fmt.Errorf("repo_id is required")
	}
	if req.Framework == "" {
		req.Framework = "colorado-ai-act"
	}

	docID := fmt.Sprintf("doc-%s-%s-%d", req.Framework, req.RepoID, time.Now().UTC().Unix())
	now := time.Now().UTC()

	var items []ReviewItem

	// 1. Green Items: Grounded Model Deployments
	for _, ev := range req.EvidenceIndex {
		citTag := report.FormatCitation(ev.AIBOMID, ev.FilePath, ev.LineNumber)
		items = append(items, ReviewItem{
			ID:               fmt.Sprintf("green-%s-%d", ev.ComponentID, ev.LineNumber),
			Category:         "Machine-Verified AI Component",
			Title:            fmt.Sprintf("System Identity: %s (%s)", ev.ModelName, ev.Kind),
			Description:      fmt.Sprintf("Static code analysis verified occurrence at `%s:%d` with confidence %.2f.", ev.FilePath, ev.LineNumber, ev.Confidence),
			Status:           StatusGreenVerified,
			EvidenceCitation: citTag,
			IsLocked:         true,
			IsAnswered:       true,
		})
	}

	// 2. Yellow & Red Items based on Control Evaluations
	for _, ev := range req.Evaluations {
		switch ev.Verdict {
		case compliancedb.VerdictMet:
			items = append(items, ReviewItem{
				ID:          fmt.Sprintf("green-ctrl-%s", ev.ControlID),
				Category:    "Automated Control Verification",
				Title:       ev.ControlID,
				Description: fmt.Sprintf("Control verified compliant against %s.", ev.StatuteRef),
				Status:      StatusGreenVerified,
				StatuteRef:  ev.StatuteRef,
				IsLocked:    true,
				IsAnswered:  true,
			})
		case compliancedb.VerdictManual:
			items = append(items, ReviewItem{
				ID:          fmt.Sprintf("yellow-ctrl-%s", ev.ControlID),
				Category:    "Human Attestation Required",
				Title:       ev.ControlID,
				Description: fmt.Sprintf("Manual attestation required for statutory requirement under %s.", ev.StatuteRef),
				Status:      StatusYellowAttestationRequired,
				StatuteRef:  ev.StatuteRef,
				IsLocked:    false,
				IsAnswered:  false,
				Options:     []string{"Standard Operational Procedure Enforced", "In-App Banner Disclosure", "Direct Written Notice", "Third-Party Audited"},
			})
		case compliancedb.VerdictGap:
			items = append(items, ReviewItem{
				ID:                      fmt.Sprintf("red-ctrl-%s", ev.ControlID),
				Category:                "Compliance Gap",
				Title:                   fmt.Sprintf("GAP: %s", ev.ControlID),
				Description:             fmt.Sprintf("Statutory gap identified under %s: %s", ev.StatuteRef, ev.GapMessage),
				Status:                  StatusRedGap,
				StatuteRef:              ev.StatuteRef,
				IsLocked:                false,
				RequiresAcknowledgement: true,
				IsAcknowledged:          false,
			})
		}
	}

	// Add standard human review items if list is minimal
	if len(items) == 0 {
		items = append(items, ReviewItem{
			ID:          "yellow-notice-delivery",
			Category:    "Human Attestation Required",
			Title:       "Consumer Notice Delivery Mechanism",
			Description: "Specify the deployment channel used to inform users of AI decisioning.",
			Status:      StatusYellowAttestationRequired,
			StatuteRef:  "CO SB 24-205 § 6-1-1704 / NYC Admin Code § 20-872",
			Options:     []string{"In-App Banner", "Direct Email Disclosure", "Website Terms of Service", "Customer Agreement"},
		})
	}

	pkg := &DocumentPackage{
		ID:          docID,
		OrgID:       req.OrgID,
		RepoID:      req.RepoID,
		Framework:   req.Framework,
		Title:       fmt.Sprintf("%s Compliance Documentation Package — %s", req.Framework, req.RepoName),
		CommitSHA:   req.CommitSHA,
		CreatedAt:   now,
		IsCertified: false,
		Items:       items,
		AIBOMSHA256: req.AIBOMSHA256,
		Metadata: map[string]string{
			"org_name":    req.OrgName,
			"repo_name":   req.RepoName,
			"signer_name": req.SignerName,
		},
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.packages[docID] = pkg
	return pkg, nil
}

// GetPackage retrieves a document package by ID.
func (a *Agent) GetPackage(docID string) (*DocumentPackage, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	pkg, exists := a.packages[docID]
	if !exists {
		return nil, fmt.Errorf("document package %q not found", docID)
	}
	return pkg, nil
}

// UpdateYellowAnswer answers a Yellow review item.
func (a *Agent) UpdateYellowAnswer(docID, itemID, value string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	pkg, exists := a.packages[docID]
	if !exists {
		return fmt.Errorf("document package %q not found", docID)
	}
	if pkg.IsCertified {
		return fmt.Errorf("cannot modify a certified document package")
	}

	for i := range pkg.Items {
		if pkg.Items[i].ID == itemID {
			if pkg.Items[i].Status != StatusYellowAttestationRequired {
				return fmt.Errorf("item %q is not a Yellow review item", itemID)
			}
			pkg.Items[i].Value = value
			pkg.Items[i].IsAnswered = (value != "")
			return nil
		}
	}
	return fmt.Errorf("item %q not found in document package", itemID)
}

// AcknowledgeRedGap acknowledges a Red compliance gap with a reason.
func (a *Agent) AcknowledgeRedGap(docID, itemID, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	pkg, exists := a.packages[docID]
	if !exists {
		return fmt.Errorf("document package %q not found", docID)
	}
	if pkg.IsCertified {
		return fmt.Errorf("cannot modify a certified document package")
	}

	for i := range pkg.Items {
		if pkg.Items[i].ID == itemID {
			if pkg.Items[i].Status != StatusRedGap {
				return fmt.Errorf("item %q is not a Red gap item", itemID)
			}
			pkg.Items[i].IsAcknowledged = (reason != "")
			pkg.Items[i].AcknowledgementReason = reason
			return nil
		}
	}
	return fmt.Errorf("item %q not found in document package", itemID)
}

// CertifyPackage executes human certification and renders regulator-ready documents.
func (a *Agent) CertifyPackage(docID string, req CertifyRequest) (*DocumentPackage, error) {
	// 1. Verify Ephemeral Human Confirmation Token
	token, err := VerifyHumanToken(a.secret, req.HumanConfirmationToken, docID)
	if err != nil {
		return nil, fmt.Errorf("human confirmation security check failed: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	pkg, exists := a.packages[docID]
	if !exists {
		return nil, fmt.Errorf("document package %q not found", docID)
	}
	if pkg.IsCertified {
		return pkg, nil // Idempotent
	}

	// 2. Apply any pending Yellow answers or Red acknowledgements in request
	for itemID, val := range req.YellowAnswers {
		for i := range pkg.Items {
			if pkg.Items[i].ID == itemID && pkg.Items[i].Status == StatusYellowAttestationRequired {
				pkg.Items[i].Value = val
				pkg.Items[i].IsAnswered = (val != "")
			}
		}
	}
	for itemID, reason := range req.RedAcknowledgements {
		for i := range pkg.Items {
			if pkg.Items[i].ID == itemID && pkg.Items[i].Status == StatusRedGap {
				pkg.Items[i].IsAcknowledged = (reason != "")
				pkg.Items[i].AcknowledgementReason = reason
			}
		}
	}

	// 3. Verify Human Readiness Blockers
	isReady, blockers := pkg.IsReadyToCertify()
	if !isReady {
		return nil, fmt.Errorf("certification blocked by unresolved items: %v", blockers)
	}

	// 4. Generate Document via ReportEngine
	now := time.Now().UTC()
	reportReq := report.ReportRequest{
		OrgID:       pkg.OrgID,
		OrgName:     pkg.Metadata["org_name"],
		RepoID:      pkg.RepoID,
		RepoName:    pkg.Metadata["repo_name"],
		CommitSHA:   pkg.CommitSHA,
		Framework:   pkg.Framework,
		SignerName:  req.UserID,
		SignerTitle: req.UserTitle,
	}

	var rep *report.ComplianceReport
	switch pkg.Framework {
	case "nyc-ll144":
		rep, err = report.GenerateNYCLL144Report(reportReq, nil)
	case "ca-ab2013":
		rep, err = report.GenerateCAAB2013Report(reportReq, nil)
	default:
		rep, err = report.GenerateColoradoReport(reportReq)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance document: %w", err)
	}

	pkg.Report = rep
	pkg.MarkdownPayload = report.RenderMarkdown(rep)
	pkg.HTMLPayload = report.RenderHTML(rep)
	pkg.IsCertified = true
	pkg.CertifiedBy = req.UserID
	pkg.CertifiedEmail = req.UserEmail
	pkg.CertifiedTitle = req.UserTitle
	pkg.CertifiedAt = &now

	// 5. Append Immutable Filing Audit Log Entry
	sigData := fmt.Sprintf("%s:%s:%s:%s", docID, req.UserID, now.Format(time.RFC3339), pkg.AIBOMSHA256)
	sigHash := sha256.Sum256([]byte(sigData))
	auditID := fmt.Sprintf("audit-%d", now.UnixNano())

	auditEntry := FilingAuditEntry{
		ID:            auditID,
		OrgID:         pkg.OrgID,
		RepoID:        pkg.RepoID,
		Framework:     pkg.Framework,
		ActionType:    "DOCUMENT_CERTIFIED",
		DocumentID:    docID,
		AIBOMSHA256:   pkg.AIBOMSHA256,
		ActorUserID:   req.UserID,
		ActorEmail:    req.UserEmail,
		HumanTokenID:  token.TokenID,
		Timestamp:     now,
		SignatureHash: hex.EncodeToString(sigHash[:]),
		Metadata:      fmt.Sprintf("Certified by %s (%s)", req.UserID, req.UserTitle),
	}

	pkg.AuditEntryID = auditID
	a.auditLogs = append(a.auditLogs, auditEntry)

	return pkg, nil
}

// GetAuditLogs returns the immutable audit trail.
func (a *Agent) GetAuditLogs() []FilingAuditEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]FilingAuditEntry{}, a.auditLogs...)
}
