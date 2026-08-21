# AIROM Compliance Platform — Executable PRD (Product Requirements Document)

> **Document Standard:** gstack /spec & /plan-eng-review Executable Product Specification.

---

## 1. Document Control & Metadata

- **Product:** AIROM Compliance Platform
- **Version:** v1.0.0-PRD
- **Status:** APPROVED FOR IMPLEMENTATION
- **Authors:** Product Architecture Team & Lead Systems Engineer
- **Target Repository:** github.com/dharmik136/airom (C:\Users\remoteadmin\airom)

---

## 2. Problem Statement & User Personas

### 2.1 Personas
1. **Alex (Staff Engineer / AI Lead):** Wants zero friction in CI/CD. Hates manual compliance spreadsheets. Needs deterministic exit codes (--fail-on gap) and actionable fix guidance (--fix).
2. **Elena (General Counsel / Chief Compliance Officer):** Legally accountable for state filings (Colorado AI Act, NYC LL 144). Needs mathematically provable time-series evidence, clear gap explanations, and drafted reports.
3. **Marcus (External Auditor / Regulator):** Needs to verify that claims in an annual attestation match production reality without reading raw source code.

---

## 3. System Architecture & Invariants

### 3.1 Non-Negotiable Invariants
1. **INV-01 (Zero Client Network on Scan):** irom scan shall never initiate outbound TCP/HTTP connections. Verified via build-dependency static analysis.
2. **INV-02 (Zero Client-Side LLM):** The CLI binary contains no LLM models or local inference runtimes.
3. **INV-03 (Decoupled Rule Updates):** Regulation packs are distributed over an ed25519-signed CDN channel and updated independently of binary releases.
4. **INV-04 (Evidence Grounding):** Every assertion in an audit report must cite a verified evidence.occurrences[] AST node.
5. **INV-05 (Human-in-the-Loop Gate):** Regulatory submissions require a one-time 90-second HMAC token generated strictly by human interaction.

---

## 4. Detailed Feature Specifications

### 4.1 Feature 1: .airomapproved Governance Primitive
- **Location:** internal/approved/ and cmd/airom/
- **CLI Commands:**
  - irom approve <purl> [--scope <glob>] [--max-temp <float>] [--max-tokens <int>]
  - irom revoke <purl> [--reason <string>]
  - irom check --approved
- **Data Model:**
  `yaml
  schema_version: "1.0"
  repo: "github.com/org/repo"
  signature: "sha256:..."
  components:
    - purl: "pkg:pypi/openai@1.51.0"
      approved_by: "elena@company.com"
      approved_at: "2026-08-21T10:00:00Z"
      scope: ["src/agents/**"]
      permitted_config:
        temperature_max: 0.5
        max_tokens_max: 2048
  `

### 4.2 Feature 2: Regulation Pack Engine (.airompack)
- **Location:** 
ules/regulations/ and pkg/airom/regulation/
- **Schema:**
  `yaml
  airom_pack_version: "1"
  pack_type: regulations
  pack_id: "us.co.ai-act.2024"
  provenance:
    statute: "Colorado HB24-1468"
    source_url: "https://leg.colorado.gov/bills/hb24-1468"
    retrieved_at: "2026-08-20T00:00:00Z"
    reviewer: "legal-review@airom.io"
  regulations:
    - id: "co.ai-act.disclosure.consequential"
      obligation_type: "disclosure"
      control:
        required_aibom_fields:
          - path: "metadata.properties[?(@.name == 'airom:deployment.disclosure_mechanism')]"
            operator: "exists"
        gap_message: "Colorado AI Act §6-1-1705(1)(a): Consumer disclosure mechanism missing."
  `

### 4.3 Feature 3: AnomalyEngine (Cloud Diff Evaluator)
- **Endpoint:** POST /api/v1/scans/diff
- **Input:** current_aibom.json + previous_aibom_hash + .airomapproved.yaml
- **Evaluation Rules:**
  1. shadow-ai: component.purl NOT IN approved.components -> Severity: HIGH
  2. model-swap: delta.model_id.changed == true AND delta.new_model NOT IN approved -> Severity: HIGH
  3. config-drift: component.config.temperature > approved.temperature_max -> Severity: MEDIUM
  4. proximity-hiring: component.location MATCHES "*(hiring|resume|candidate)*" -> Severity: HIGH (NY LL144 Trigger)

### 4.4 Feature 4: ReportEngine (Evidence-Anchored Prose)
- **Endpoint:** POST /api/v1/reports/generate
- **Pipeline:**
  1. Ingest AIBOM + Compliance Verdicts.
  2. Construct prompt with strict citation constraints.
  3. LLM drafts section prose.
  4. Post-processing AST citation verifier validates all [ev:...] tags against AIBOM occurrences.
  5. Render via Typst into PDF, HTML, Word DOCX, and Markdown.

### 4.5 Feature 5: FilingAgent (Green/Yellow/Red Review Gateway)
- **UI State Machine:**
  - **GREEN (Met):** Locked pre-filled fields with AIBOM source links.
  - **YELLOW (Manual):** Interactive human attestation fields (Required).
  - **RED (Gap):** Blocking gap requiring resolution or explicit signed acknowledgement.
- **Submit Action:** Requires POST /api/v1/filings/{id}/submit with human_confirmation_token (HMAC with 90s TTL).

---

## 5. Security & Threat Modeling (CSO Review)

| Threat Category (STRIDE) | Attack Scenario | Architectural Defense |
|---|---|---|
| **Spoofing** | Attacker tampers with local regulation pack to falsely report 100% compliance | ed25519 digital signature verified against embedded public key before loading. |
| **Tampering** | Rogue developer manually alters .airomapproved to bypass CI gates | SHA-256 manifest signature check on load; fails if edited without CLI signature. |
| **Repudiation** | Company claims an automated filing was made in error without authorization | Append-only audit log with user identity, IP address, and HMAC confirmation token. |
| **Information Disclosure** | Cloud service leaks customer proprietary source code | Scanner never transmits code. Only AIBOM component metadata crosses trust boundary. |
| **Denial of Service** | Malicious nested code constructs cause scanner to OOM in CI | Bounded 32KB sampling, read-once streaming, and clamped goroutine worker pool. |
| **Elevation of Privilege** | CI runner executes malicious serialized model weights | Zero model execution invariant: models parsed via binary header magic bytes only. |
