# AIROM Compliance Platform — Granular Implementation Backlog

> **Document Standard:** Atomic, measurable, task-by-task engineering tickets ready for immediate development.

---

## Track 1: Core Scanner & CLI Engine (Go)

### Task 1.1.1: .airomapproved Manifest Data Model & Parser
- **File:** internal/approved/manifest.go
- **Package:** package approved
- **Structs:**
  `go
  type ComponentApproval struct {
      PURL            string            yaml:"purl"
      ApprovedBy      string            yaml:"approved_by"
      ApprovedAt      time.Time         yaml:"approved_at"
      Scope           []string          yaml:"scope"
      PermittedConfig map[string]string yaml:"permitted_config,omitempty"
  }

  type ApprovedManifest struct {
      SchemaVersion string              yaml:"schema_version"
      Repo          string              yaml:"repo"
      Signature     string              yaml:"signature"
      Approved      []ComponentApproval yaml:"approved"
      Deny          []ComponentApproval yaml:"deny,omitempty"
  }
  `
- **Functions:**
  - unc LoadManifest(path string) (*ApprovedManifest, error)
  - unc (m *ApprovedManifest) ValidateSignature(secret []byte) bool
  - unc (m *ApprovedManifest) IsApproved(purl string, filePath string) (bool, string)
- **Unit Tests:** internal/approved/manifest_test.go (Valid load, Tampered signature, Scope match, Path mismatch).

---

### Task 1.1.2: irom approve & irom revoke CLI Subcommands
- **File:** internal/cli/approve.go & internal/cli/revoke.go
- **Command Signatures:**
  - irom approve <purl> [--scope <glob>] [--max-temp <val>]
  - irom revoke <purl> [--reason <msg>]
- **Logic:**
  1. Inspect local .airomapproved in repo root (or initialize if absent).
  2. Append/update component approval record with current user info from git config user.email.
  3. Recompute manifest SHA-256 signature.
  4. Write back formatted YAML atomically.
- **Unit Tests:** internal/cli/approve_test.go (CLI arg parsing, file creation, idempotency).

---

### Task 1.1.3: Shadow AI Detection in Assembler Pipeline
- **File:** internal/assemble/assemble.go
- **Logic:**
  1. Assembler loads .airomapproved if present in scan target root.
  2. For each assembled component, evaluate manifest.IsApproved(comp.PURL, occ.Location.File).
  3. If unapproved, append irom:governance.status = "unapproved" to component properties.
  4. Emit high-severity finding: SHADOW_AI_DETECTED with occurrence location.
- **Unit Tests:** Golden fixture test in 	estdata/fixtures/shadow_ai_project/.

---

## Track 2: Regulatory Intelligence & Regulation Packs

### Task 2.1.1: Regulation Pack Definition & YAML Schema
- **File:** pkg/airom/regulation/schema.go
- **Structs:**
  `go
  type ControlDirective struct {
      RequiredFields []FieldSelector yaml:"required_aibom_fields"
      GapMessage     string          yaml:"gap_message"
      RemediationURL string          yaml:"remediation_url"
  }

  type RegulationEntry struct {
      ID                   string           yaml:"id"
      Title                string           yaml:"title"
      SourceSection        string           yaml:"source_section"
      SourceURL            string           yaml:"source_url"
      ObligationType       string           yaml:"obligation_type"
      PenaltyTier          string           yaml:"penalty_tier"
      Control              ControlDirective yaml:"control"
  }

  type RegulationPack struct {
      PackVersion string            yaml:"airom_pack_version"
      PackID      string            yaml:"pack_id"
      Provenance  ProvenanceBlock   yaml:"provenance"
      Regulations []RegulationEntry yaml:"regulations"
  }
  `
- **Unit Tests:** pkg/airom/regulation/schema_test.go.

---

### Task 2.1.2: Colorado AI Act (HB24-1468) Pack Implementation
- **File:** 
ules/regulations/us-co-ai-act.yaml
- **Controls Included:**
  1. co.ai-act.disclosure.consequential (Consumer disclosure for high-risk credit/employment/healthcare AI).
  2. co.ai-act.risk-assessment.annual (Annual algorithmic impact assessment documentation).
  3. co.ai-act.appeal.mechanism (Human review & appeal pathway).
- **Test:** Run irom scan testdata/fixtures/co_compliant_app --compliance colorado-ai-act -> Assert all controls MET.

---

### Task 2.1.3: ed25519 Cryptographic Signature Verification
- **File:** internal/ruleengine/verify.go
- **Logic:**
  - Verify detached .sig against embedded irom_pubkey.pem.
  - Fail closed: reject corrupted or unsigned regulation packs.
- **Unit Tests:** internal/ruleengine/verify_test.go (Valid signature, Corrupted payload, Expired key).

---

## Track 3: ComplianceDB & State Ledger

### Task 3.1.1: PostgreSQL Append-Only Time-Series Schema
- **File:** migrations/001_compliance_db_init.sql
- **Tables:** organizations, 
epositories, scan_snapshots, control_evaluations, compliance_incidents, iling_audit_log.
- **Security:** REVOKE UPDATE, DELETE ON scan_snapshots, filing_audit_log FROM api_role;

### Task 3.1.2: Hash-Chain Snapshot Generator
- **File:** services/compliancedb/snapshot.go
- **Logic:**
  `go
  func ComputeSnapshotHash(scanID string, ts time.Time, aibomHash string, controls Summary, prevHash string) string {
      payload := fmt.Sprintf("%s|%s|%s|%s|%s", scanID, ts.UTC().Format(time.RFC3339), aibomHash, controls.Hash(), prevHash)
      sum := sha256.Sum256([]byte(payload))
      return hex.EncodeToString(sum[:])
  }
  `

---

## Track 4: AnomalyEngine & Cloud Diff Service

### Task 4.1.1: Semantic AIBOM Diff Processor
- **File:** services/anomaly/diff.go
- **Input:** ase_inventory *airom.Inventory, head_inventory *airom.Inventory
- **Output:** DiffReport{ Added: [], Removed: [], Modified: [] }

### Task 4.1.2: Rule-Based Anomaly Matcher
- **File:** services/anomaly/matcher.go
- **Rules Evaluated:** shadow-ai, model-swap, config-drift, proximity-hiring.

---

## Track 5: ReportEngine & Evidence Grounding

### Task 5.1.1: Evidence Citation AST Verifier
- **File:** services/report/verifier.go
- **Logic:**
  - Parse generated markdown prose for \[ev:([^\]]+)\].
  - Verify each citation ID exists in the input AIBOM evidence.occurrences[].
  - Strip uncited factual claims or replace with [MANUAL ATTESTATION REQUIRED].

### Task 5.1.2: Typst PDF Template Generator
- **File:** services/report/templates/colorado_ai_act.typ
- **Output:** Publication-grade PDF with table of contents, evidence appendix, and legal signature blocks.

---

## Track 6: FilingAgent & Human Gate UI

### Task 6.1.1: Colorado AG REST API Connector
- **File:** services/filing/adapters/colorado_ag.go
- **Implements:** FilingAdapter interface (Prepare, Validate, Submit).
- **Security:** Checks ValidateHumanToken(token) before sending HTTP POST.

### Task 6.1.2: Green/Yellow/Red Interactive Review Component
- **File:** web/components/filing/ReviewScreen.tsx
- **Features:** Locked Green sections, required Yellow attestation inputs, gap-acknowledgment modals, disabled Submit button.
