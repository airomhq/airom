# AIROM Compliance Platform — Rigid Sprint Implementation Plan

This is the single source of truth for what gets built, in what order, by whom, with exact acceptance criteria.

CRITICAL CORRECTIONS FROM RESEARCH:
1. California SB 1047 was VETOED — remove all references
2. Most states have NO filing portals — compliance is documentation-on-demand (CO) or public website posting (NYC LL144, CA AB 2013)
3. Adding compliance frameworks to AIROM requires ZERO Go code — just YAML in `specs/`
4. The assembler injection point for `.airomapproved` is `draft.finish()` in `internal/assemble/assemble.go`
5. CLI follows standard Cobra `newXxxCmd()` pattern in `internal/cli/commands.go`

## Phase 0: Sprint 0 (Week 0-1) — Project Bootstrap

### Task P0-01: Fork & Branch Strategy
- Create `develop` branch from `main`
- Branch naming: `feature/<track>/<short-name>` (e.g., `feature/t1/airomapproved-parser`)
- PR target: all PRs merge to `develop`, release branches cut from `develop`
- Acceptance: `git branch -a` shows `develop` and `upstream/main`

### Task P0-02: CI Pipeline Extension
- Add governance CI checks to `.github/workflows/`:
  - `go list -deps ./cmd/scan/... | grep net/http` must exit 0 (zero network in scan)
  - `grep -rn 'auto_submit\|AUTO_SUBMIT' --include='*.go' --include='*.yaml' src/` must find 0 results
- Acceptance: CI pipeline passes on empty PR to develop

---

## Phase 1: Sprints 1-3 (Weeks 2-7) — Core Governance Engine

### Sprint 1 (Weeks 2-3): `.airomapproved` Foundation

#### Task S1-01: `.airomapproved` Data Model & Parser
- Create: `internal/approved/manifest.go`
- Structs: `ApprovedManifest`, `ComponentApproval` with PURL, ApprovedBy, ApprovedAt, Scope (glob patterns), PermittedConfig (temperature_max, max_tokens_max)
- Functions: `LoadManifest(path) (*ApprovedManifest, error)`, `IsApproved(purl, filePath) (bool, string)`, `ValidateSignature(secret) bool`
- Create: `internal/approved/manifest_test.go`
- Test cases: Valid load, tampered signature detection, scope glob matching, path mismatch rejection, missing file returns nil (not error)
- Acceptance: `go test ./internal/approved/...` passes with 100% case coverage

#### Task S1-02: `airom approve` CLI Subcommand
- Create: `internal/cli/approve.go`
- Command: `airom approve <purl> [--scope <glob>] [--max-temp <float>] [--max-tokens <int>]`
- Logic: Load `.airomapproved` (or initialize), append component with `git config user.email` as approver, recompute SHA-256 signature, write YAML atomically
- Register in `internal/cli/cli.go` inside `newRootCmd()`
- Acceptance: Running `airom approve pkg:pypi/openai@1.51.0 --scope 'src/**'` creates/updates `.airomapproved` with correct entry

#### Task S1-03: `airom revoke` CLI Subcommand
- Create: `internal/cli/revoke.go`
- Command: `airom revoke <purl> [--reason <msg>]`
- Logic: Move component from `approved` to `revocations` list with timestamp and reason
- Acceptance: Revoking an approved component moves it and next scan flags it

#### Task S1-04: `.airomapproved` Golden Fixture
- Create: `testdata/fixtures/approved_project/` with `.airomapproved`, `src/app.py`, `requirements.txt`
- Covers: 2 approved components, 1 unapproved (shadow AI), 1 with config drift
- Acceptance: Golden fixture test produces deterministic output matching expected

### Sprint 2 (Weeks 4-5): Shadow AI Detection & Assembler Integration

#### Task S2-01: Assembler Governance Injection
- Modify: `internal/assemble/assemble.go`
- In `draft.finish()`: Load `.airomapproved` from scan target root, evaluate each component against manifest
- Add property: `airom:governance.status` = `approved` | `unapproved` | `config-drift`
- For unapproved: emit high-severity finding `SHADOW_AI_DETECTED`
- For config-drift (e.g., temperature > permitted max): emit medium-severity finding `CONFIG_DRIFT_DETECTED`
- Acceptance: Scanning `testdata/fixtures/approved_project/` produces correct governance properties on all 4 components

#### Task S2-02: `airom check --approved` Command
- Create or extend: `internal/cli/check.go`
- Command: `airom check --approved` — runs scan and filters output to governance findings only
- Exit code 1 if any SHADOW_AI or CONFIG_DRIFT findings
- Acceptance: Returns exit 0 on fully approved project, exit 1 on project with shadow AI

#### Task S2-03: SARIF Governance Annotations
- Modify: SARIF writer to include `SHADOW_AI_DETECTED` and `CONFIG_DRIFT_DETECTED` as SARIF results
- Maps to GitHub Code Scanning alerts in PRs
- Acceptance: Generated SARIF contains governance findings with correct rule IDs

### Sprint 3 (Weeks 6-7): Colorado AI Act Compliance Pack

#### Task S3-01: Colorado AI Act Compliance Spec
- Create: `internal/compliance/specs/colorado-ai-act.yaml`
- Controls:
  - `co.ai-act.risk-mgmt` (§6-1-1702): verdict `manual` — "Confirm risk management program aligned with NIST AI RMF"
  - `co.ai-act.impact-assessment` (§6-1-1703): verdict `met` if assessment_date exists and < 365 days old, `gap` otherwise
  - `co.ai-act.consumer-notice` (§6-1-1704): verdict `manual` — "Confirm consumer notification mechanism exists in deployment UI"
  - `co.ai-act.incident-reporting` (§6-1-1705): verdict `manual` — "Confirm algorithmic discrimination reporting process to CO AG within 90 days"
- ZERO Go code changes needed (//go:embed specs/*.yaml picks it up automatically)
- Acceptance: `airom scan . --compliance colorado-ai-act` produces correct control verdicts

#### Task S3-02: NYC Local Law 144 Compliance Spec
- Create: `internal/compliance/specs/nyc-ll144.yaml`
- Controls:
  - `nyc.ll144.bias-audit`: verdict `met` if last_audit_date < 1 year, `gap` otherwise
  - `nyc.ll144.public-posting`: verdict `manual` — "Confirm bias audit summary posted on careers page"
  - `nyc.ll144.candidate-notice`: verdict `manual` — "Confirm 10-day advance notice sent to NYC candidates"
  - `nyc.ll144.impact-ratio`: verdict `met` if impact_ratio data present, `gap` otherwise
- Acceptance: Running compliance scan against employment AI fixture produces correct verdicts

#### Task S3-03: CA AB 2013 Compliance Spec
- Create: `internal/compliance/specs/ca-ab2013.yaml`
- Controls:
  - `ca.ab2013.training-data-disclosure`: verdict `met` if training_data_summary exists, `gap` otherwise
  - `ca.ab2013.pii-disclosure`: verdict `met` if contains_pii field declared, `gap` otherwise
- Acceptance: `airom scan . --compliance ca-ab2013` produces correct verdicts

#### Task S3-04: Compliance Pack Test Fixtures
- Create: `testdata/fixtures/co_compliant_app/` — app with all CO controls met
- Create: `testdata/fixtures/co_noncompliant_app/` — app missing impact assessment
- Create: `testdata/fixtures/nyc_employment_app/` — employment AEDT with bias audit data
- Acceptance: Golden tests pass deterministically for all three fixtures

---

## Phase 2: Sprints 4-6 (Weeks 8-13) — Cloud Intelligence Layer

### Sprint 4 (Weeks 8-9): Cloud Diff Engine & Anomaly Rules

#### Task S4-01: AIBOM Semantic Diff Processor
- Create: `services/anomaly/diff.go` (new cloud service module)
- Input: Two CycloneDX AIBOM JSONs (base and head)
- Output: `DiffReport{Added: []Component, Removed: []Component, Modified: []ComponentDelta}`
- Acceptance: Diff of two AIROM scan outputs correctly identifies added/removed/changed components

#### Task S4-02: Rule-Based Anomaly Matcher
- Create: `services/anomaly/matcher.go`
- Rules (YAML-evaluated):
  - `shadow-ai`: component in head but not in `.airomapproved` -> HIGH
  - `model-swap`: model_id changed without approval -> HIGH
  - `config-drift`: temperature/max_tokens exceeds permitted bounds -> MEDIUM
  - `proximity-hiring`: AI in paths matching hiring/resume/candidate/ats -> HIGH
  - `proximity-credit`: AI in paths matching credit/lending/underwriting -> HIGH
  - `proximity-healthcare`: AI in paths matching patient/clinical/ehr -> HIGH
- Acceptance: Each rule has a positive and negative test case

### Sprint 5 (Weeks 10-11): ComplianceDB MVP

#### Task S5-01: PostgreSQL Schema Design
- Create: `migrations/001_compliance_db_init.sql`
- Tables: organizations, repositories, scan_snapshots (append-only), control_evaluations, compliance_incidents
- Security: `REVOKE UPDATE, DELETE ON scan_snapshots FROM api_role;`
- Acceptance: Migration runs cleanly on PostgreSQL 15+

#### Task S5-02: Hash-Chain Snapshot Generator
- Create: `services/compliancedb/snapshot.go`
- Formula: `self_hash = SHA256(scan_id | timestamp | aibom_hash | controls_hash | prev_hash)`
- Acceptance: Tampered historical snapshot detected by chain validator

### Sprint 6 (Weeks 12-13): Dashboard MVP & Integration

#### Task S6-01: Web Dashboard API
- Create: API endpoints for compliance status per org/repo
- `GET /api/v1/orgs/{org}/compliance` -> aggregate met/gap/manual counts per regulation
- `GET /api/v1/repos/{repo}/history` -> time-series compliance snapshots
- Acceptance: API returns correct data from ComplianceDB

#### Task S6-02: GitHub Action v1
- Create: `airomhq/airom-action@v1` on GitHub Marketplace
- Zero-config: `uses: airomhq/airom-action@v1` with `api-key` secret
- Produces: SARIF upload + compliance status comment on PR
- Acceptance: Test repository PR gets automated compliance comment

---

## Phase 3: Sprints 7-9 (Weeks 14-19) — Reports & Documentation Engine

### Sprint 7-8: ReportEngine
- Cloud-only LLM report generation
- Evidence citation verifier (strips uncited claims)
- Colorado AI Act annual attestation template
- NYC LL144 public bias audit summary template (HTML for website posting)
- On-prem Docker container with BYOK LLM support

### Sprint 9: Documentation & Public Posting Agent
- Renamed from FilingAgent: ComplianceDocumentAgent
- Generates regulator-ready documentation packages on demand
- Produces public HTML pages for NYC LL144 website posting requirement
- Green/Yellow/Red review UI for human attestation of manual controls

---

## Phase 4: Sprints 10-12 (Weeks 20-25) — Enterprise & Scale

### Sprint 10-11: Enterprise Features
- SSO (SAML/OIDC) via WorkOS/Auth0
- RBAC (admin, compliance officer, developer, auditor)
- IL BIPA, TX TRAIGA, VA VCDPA compliance specs
- Phase 2 state expansion (7 additional states)

### Sprint 12: Enterprise Launch
- SOC 2 Type I readiness
- Enterprise pricing activation ($24K ACV)
- Sales playbook and 14-day POC process

---

## Appendix: Definition of Done (Global)

Every task must meet ALL of these before merge:
1. `go test ./...` passes (zero failures)
2. `go vet ./...` clean
3. No new `net/http` imports in `cmd/scan/` dependency tree
4. Golden fixture tests updated if output format changed
5. PR description includes: what changed, why, acceptance criteria result
6. No `auto_submit` or `AUTO_SUBMIT` strings introduced (CI grep check)
