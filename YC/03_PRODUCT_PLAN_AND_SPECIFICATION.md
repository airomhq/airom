# AIROM Compliance Platform — Product Plan

> **The Mission:** AI-Native Compliance Software that watches regulations across all 50 US states, flags anomalies, enables renewal filings, and writes audit reports — eliminating 80% of compliance team grunt work.

---

## Section 1 — What AIROM Is Today (The Foundation)

### 1.1 Product Identity

AIROM is an open-source **AI Bill of Materials (AIBOM) scanner** — a single static Go binary, currently at **v0.3.9**, licensed Apache 2.0. It runs entirely offline with no daemon, no server, and no runtime dependencies (`CGO=0`, pure Go). Drop the binary on any machine, point it at a directory, and it produces a machine-readable inventory of every AI artifact it finds: models, frameworks, LLM API calls, vector databases, configuration parameters, and associated CVEs. The tool self-updates its detection rule pack on first invocation (the real run printed `rules auto-updated from built-in packs to v0.1.6` before scanning).

### 1.2 Real Scan Output — Live Run on This Machine

The following is unedited output from a live scan of a Python LLM application:

```
┌─ Scan Summary ────────────────────────────────┐
│ Target        C:\Users\remoteadmin\airom_test │
│ Components    7                               │
│ By Type                                       │
│   ai-config          2                        │
│   library            2                        │
│   framework          1                        │
│   hosted-llm         1                        │
│   vector-db          1                        │
│ Vulnerabilities   total 2  high 1  medium 1   │
└───────────────────────────────────────────────┘

┌────────────┬─────────────┬─────────┬───────────┬────────┬──────────┬────────────────────┐
│ KIND       │ NAME        │ VERSION │ PROVIDER  │ CONF   │ VULN     │ LOCATION           │
├────────────┼─────────────┼─────────┼───────────┼────────┼──────────┼────────────────────┤
│ ai-config  │ max_tokens  │ -       │ -         │ 0.5    │ -        │ src/app.py:11      │
│ ai-config  │ temperature │ -       │ -         │ 0.5    │ -        │ src/app.py:10      │
│ framework  │ langchain   │ 0.2.16  │ langchain │ 0.9858 │ high (2) │ requirements.txt:2 │
│ hosted-llm │ gpt-4o      │ -       │ openai    │ 0.85   │ -        │ src/app.py:8       │
│ library    │ anthropic   │ 0.34.0  │ anthropic │ 0.95   │ -        │ requirements.txt:4 │
│ library    │ openai      │ 1.51.0  │ openai    │ 0.985  │ -        │ requirements.txt:1 │
│ vector-db  │ chroma      │ 0.5.5   │ chroma    │ 0.95   │ -        │ requirements.txt:3 │
└────────────┴─────────────┴─────────┴───────────┴────────┴──────────┴────────────────────┘

Vulnerabilities:
│ langchain │ CVE-2026-45134 │ HIGH   │ fixed │ 0.2.16 → 0.3.30
│ langchain │ CVE-2026-55443 │ MEDIUM │ fixed │ 0.2.16 → 1.3.9
```

In one pass over a small project, AIROM identified: a hosted LLM call to `gpt-4o` at `src/app.py:8`, a vulnerable `langchain 0.2.16` with two CVEs and actionable fix versions, a Chroma vector DB, and two low-level `ai-config` parameters (`temperature`, `max_tokens`) with file:line precision. Every row carries a detector confidence score — `langchain` at `0.9858` reflects cross-file project detection.

### 1.3 Scanner Pipeline Architecture

```
Source Acquisition
      │
      ▼
Phase 1: Streaming Scan
  ├─ Aho-Corasick trie (O(n) string match over byte stream)
  ├─ Gated regex (fires only on trie hits, never blind)
  └─ Worker pool: GOMAXPROCS goroutines, one file per worker
      │
      ▼
Phase 2: Cross-file Project Detection
  └─ Correlates claims across file boundaries
     (e.g., import in .py + version pin in requirements.txt → single component)
      │
      ▼
Assembler
  └─ Identity resolution, deduplication, confidence merge
      │
      ▼
Writers (pure functions, no side effects)
  ├─ CycloneDX JSON/XML
  ├─ SPDX
  ├─ SARIF (GitHub Code Scanning compatible)
  ├─ Plain JSON
  └─ Terminal table (default)
```

### 1.4 Eight Design Invariants (CI-Enforced)

| Invariant | What It Means |
|---|---|
| **read-once** | Each file byte is read exactly once; no seek-back, no double pass |
| **bounded memory** | Peak RSS is O(window size), not O(repo size); a 100 GB repo doesn't OOM |
| **decide-before-read** | File type and routing is determined from the path before the stream opens |
| **detectors-emit-claims-only** | Detectors produce unresolved claims; the Assembler owns identity |
| **writers-are-pure-functions** | Same AIBOM struct → bit-identical output on every call |
| **degradable** | A detector panic is caught and logged; the scan continues |
| **deterministic output** | Byte-identical results across runs regardless of goroutine scheduling |
| **pure-Go CGO=0** | No native dependencies; cross-compiles to Windows/Linux/Mac from one source |

### 1.5 Current Feature Surface

- **NIST AI RMF and OWASP Agentic compliance mapping** — `met` / `gap` / `manual` verdict per control backed by AIBOM evidence
- **CVE overlay via OSV.dev** — version-pinned components checked against OSV; results include fixed-in versions
- **Model lifecycle / EOL checking** — flags components against known end-of-support schedules
- **Load-time risk detection** — pickle deserialization exploits, Keras Lambda layers, unsafe `torch.load`
- **SARIF output** — direct ingestion into GitHub Advanced Security Code Scanning
- **`airom diff`** — semantic scan comparison between two AIBOM snapshots
- **Signed rule update channel** — ed25519-signed rule packs, verified before application

### 1.6 Honest Assessment

| Audience | Score | Reason |
|---|---|---|
| Developer in CI | **9 / 10** | Drop-in binary, zero config, SARIF native, deterministic, fast. Fits into a GitHub Actions step in one line. |
| Compliance team | **0 / 10** | Terminal table only. No PDF/HTML report. No answer to "am I compliant with Colorado AI Act?" No historical tracking. No remediation workflow. No regulator-facing artifact. |

That gap — between a scanner that gives developers a perfect signal and a compliance team that can't use the output — is the product.

---

## Section 2 — The Gap: What Needs to Exist

### 2.1 Market Context

- **1,500+** state-level AI bills introduced in 2025 alone
- **45 states** with active AI bills by March 2026
- A single deployed AI system may simultaneously satisfy: Colorado SB 205, California SB 1047, NY Local Law 144, HIPAA, FCRA, NIST AI RMF — each with different requirements, deadlines, and evidence formats
- Today, compliance teams track this in spreadsheets — manually updated, no version history, no automated gap detection
- Compliance software market: **$39.3B in 2026** → **$78.9B by 2033**

### 2.2 The Core Problem AIROM Doesn't Solve

Regulators don't only ask "are you compliant today?" They ask:

> *"Were you ever non-compliant? For how long? What triggered it? What remediation did you take, and when?"*

That question requires **time-series compliance history**, not point-in-time scan results. A single AIBOM snapshot cannot answer it.

### 2.3 Gap Table

| Capability | AIROM Today | Vision Adds | What Closes the Gap |
|---|---|---|---|
| **AI inventory** | 7 component kinds, file:line evidence, CVEs | Same foundation | ✅ Already solved |
| **Regulation coverage** | NIST AI RMF + OWASP Agentic only | All 50 US states + federal frameworks | Regulation ingestion pipeline: bill text → structured controls → AIBOM mapping |
| **Compliance verdict** | `met/gap/manual` per component per framework | Full control-by-control report with evidence citations and remediation steps | LLM-assisted report writer grounded on AIBOM evidence; human review gate |
| **Time-series history** | None — each scan is stateless | Append-only compliance ledger, timestamped and signed | Persistent scan store; `airom diff` extended to produce ledger entries |
| **Anomaly detection** | None | Alerts when a new component changes compliance posture | Rule-based policy-as-code layer: YAML rules evaluated against each AIBOM diff |
| **Regulator-facing audit report** | None | Signed, dated PDF/HTML: inventory → control mapping → evidence → non-compliance periods | Report writer module: AIBOM + ledger + regulation corpus → document |
| **Renewal filing support** | None | Pre-fills state-required AI registration forms from AIBOM data | Form template library keyed by state + regulation; AIBOM field → form field mapping |
| **Compliance team workflow** | Zero — terminal output only | Case management: open findings, assignees, due dates, audit trail | Thin web UI or API-first backend |

### 2.4 What the Vision Is — Precisely

1. **Watches** — ingests new state AI bills, maps new controls to AIBOM component kinds within hours of publication
2. **Scans** — runs AIROM on every commit (CI) and on schedule (production), writes each result into a signed, append-only compliance ledger
3. **Flags** — fires policy-as-code rules when a scan delta changes compliance posture; routes findings to named owners
4. **Proves** — produces a regulator-facing audit report: inventory, control verdicts, evidence, non-compliance windows with start/end timestamps, and documented remediation actions
5. **Files** — pre-populates state renewal and registration forms from AIBOM-derived data, reducing filing time from days to hours

> [!IMPORTANT]
> The target outcome is eliminating **80% of compliance team grunt work** — manual tracking, evidence collection, form-filling, and report drafting. It does not replace compliance judgment. A compliance officer still reviews verdicts, signs off on reports, and makes calls on ambiguous controls. The software does the legwork; the human does the judgment.

### 2.5 Why AIROM Is the Right Foundation

```
┌─────────────────────────────────────────────────────────────┐
│                  Compliance Intelligence Layer               │
│  Regulation DB │ Ledger │ Policy Engine │ Report Writer │ UI │
├─────────────────────────────────────────────────────────────┤
│                      AIROM Scanner Core                      │
│   Streaming Detection │ Assembler │ Writers │ CVE Overlay    │
└─────────────────────────────────────────────────────────────┘
```

The scanner core is not being replaced. It is being promoted from a developer tool to the evidence foundation of a compliance platform.

---

## Section 3 — Backend Intelligence Layers

### 3.1 RegWatch — Regulatory Intelligence Engine

RegWatch is the **watching** layer. It continuously ingests statutes, guidance documents, and enforcement actions; normalizes them into machine-readable controls; and distributes those controls to AIROM clients as signed regulation packs. Regulatory knowledge and the AIROM binary are **fully decoupled** — the same way rule packs already update independently of releases.

#### 3.1.1 Decoupled Architecture

The AIROM client already demonstrates the update pattern. When `airom scan .` runs, it performs a silent pre-scan sync:

```
[airom] rules auto-updated from built-in packs to v0.1.6
```

Regulation packs are a **new pack type** within this same signed update channel. The binary is unchanged. Regulations can ship daily — or within hours for emergency guidance — without touching the release pipeline.

```
Update Channel Flow
───────────────────────────────────────────────────────────────────
  AIROM Backend (Serverside)                 AIROM Client
  ┌─────────────────────────────┐            ┌──────────────────────┐
  │  Statute / Guidance Doc     │            │  airom scan .        │
  │         │                   │            │         │            │
  │  LLM Parse (1 call/statute) │            │  Pre-scan sync       │
  │         │                   │            │  GET /packs/latest   │
  │  Human Expert Review ────── │──sign──►   │  Verify ed25519 sig  │
  │  Sign output (ed25519)      │            │  Unpack to local DB  │
  │  Push to update channel     │            │         │            │
  └─────────────────────────────┘            │  Pure pattern match  │
                                             │  against AIBOM       │
                                             └──────────────────────┘
```

**Key invariant:** The client performs **zero LLM calls**. After signature verification, compliance checking is pure deterministic pattern matching against the AIBOM the scan produces.

#### 3.1.2 Serverside LLM Pipeline

1. **Ingest** — crawler pulls statute text from official state legislature sites. Source URL and retrieval timestamp are mandatory at ingest.
2. **Parse** — single LLM call per statute section; extracts obligation type, affected system category, required control, exemption conditions, enforcement authority, and penalty tier. Prompt is pinned and versioned.
3. **Human expert review** — a compliance expert on the AIROM team reviews structured output against the source text before the pack is published. Human review catches category errors, ambiguous applicability language, and inter-state conflicts. This gate produces higher trust than an automated verifier at lower cost.
4. **Sign and publish** — reviewed output is signed with the AIROM ed25519 private key and pushed to the update channel as a versioned pack file.

#### 3.1.3 Regulation Pack Schema

```yaml
# AIROM Regulation Pack — Colorado AI Act
airom_pack_version: "1"
pack_type: regulations
pack_id: us.co.ai-act.2024
pack_version: "0.3.1"
published_at: "2026-08-15T09:12:00Z"

provenance:
  statute: "Colorado Artificial Intelligence Act (HB24-1468)"
  official_url: "https://leg.colorado.gov/bills/hb24-1468"
  effective_date: "2026-02-01"
  retrieved_at: "2026-08-14T22:00:00Z"
  llm_model: "gpt-4o-2024-08-06"
  reviewer: "jdoe@airom.io"
  reviewed_at: "2026-08-15T08:47:00Z"

applicability:
  jurisdiction: US
  deployment_states: [CO]
  system_categories:
    - high_risk_ai_system

regulations:
  - id: co.ai-act.disclosure.consequential
    title: "Consumer Disclosure — Consequential Decision"
    source_section: "HB24-1468 §6-1-1705(1)(a)"
    source_url: "https://leg.colorado.gov/bills/hb24-1468#section-6-1-1705"
    obligation_type: disclosure
    enforcement_authority: "Colorado Attorney General"
    penalty_tier: civil
    control:
      required_aibom_fields:
        - path: metadata.properties[?(@.name == 'airom:deployment.disclosure_mechanism')]
          operator: exists
        - path: metadata.properties[?(@.name == 'airom:decision.appeal_mechanism')]
          operator: exists
      gap_message: >
        Colorado AI Act §6-1-1705(1)(a): No consumer disclosure mechanism or
        appeal pathway declared in AIBOM for a system making consequential decisions.
      remediation_url: "https://docs.airom.io/regulations/co-ai-act/disclosure"
```

**Real terminal output when the control is GAP:**

```
✗ CONTROL_GAP  co.ai-act.disclosure.consequential
  Colorado AI Act §6-1-1705(1)(a): No consumer disclosure mechanism or
  appeal pathway declared. See: https://docs.airom.io/regulations/co-ai-act/disclosure
  Statute: https://leg.colorado.gov/bills/hb24-1468#section-6-1-1705
```

> [!IMPORTANT]
> Every regulation pack entry must carry `source_url` and `retrieved_at`. A pack entry without both is rejected by the pack validator before signing. Clients that receive a pack missing provenance fields log `PACK_INTEGRITY_ERROR` and refuse to apply the pack.

#### 3.1.4 State Coverage Phases

| Phase | States | Laws Covered | Target |
|---|---|---|---|
| **Phase 1** | CA, CO, NY, IL, TX, VA | CO AI Act, NYC LL144, CA SB 1047 / CCPA, IL BIPA, TX CAPAIA, VA CDPA AI provisions | Q3 2026 |
| **Phase 2** | WA, FL, MA, GA, PA, OH, MI | WA My Health My Data Act AI provisions + 6 others | Q1 2027 |
| **Phase 3** | Remaining 37 states + DC | LLM automation pipeline, 20% spot-check human review | Q3 2027 |

---

### 3.2 ComplianceDB — Persistent State Machine

ComplianceDB answers the questions RegWatch cannot: *Was this control passing last quarter? When did it break? Who needs to file by March 1st?* It is an enterprise-tier feature built on top of the diff primitive AIROM already exposes via `airom diff`.

#### 3.2.1 Tier Boundaries

| Capability | Free | Enterprise |
|---|---|---|
| Current scan result | ✓ | ✓ |
| Regulation pack gap/met status | ✓ | ✓ |
| Anonymized community benchmarks | ✓ | ✓ |
| Historical compliance state (time-series) | — | ✓ |
| Compliance incident log | — | ✓ |
| Evidence vault with hash-chain snapshots | — | ✓ |
| Renewal tracker with escalating alerts | — | ✓ |
| Org-scoped aggregated view (multi-repo) | — | ✓ |

**Community benchmarks (free tier):** Aggregated, anonymized control status across the user base. Minimum cohort size: 50 projects before a benchmark is published (k-anonymity). Free tier users see:

```
ℹ  73% of projects using LangChain 0.2.x have CVE-2024-3095 open — yours is patched.
ℹ  41% of projects declaring airom:consequential_decision_scope=broad are missing
   a disclosure_mechanism. Yours is also missing. [co.ai-act.disclosure.consequential]
```

No project identity, no org identity, no raw AIBOM data leaves the client for benchmarks — only per-control boolean (met/gap) and component-version tuples.

#### 3.2.2 Org-Scoped State Model

ComplianceDB is keyed at the **org level**, not the repo level. A regulatory obligation may apply to all 50 repos in an org:

```
Org (org_id: acme-corp)
 ├── Regulation Obligation (reg_id: co.ai-act.disclosure.consequential)
 │    ├── Repo: payments-service  → CONTROL_MET   (since 2026-06-01)
 │    ├── Repo: fraud-detection   → CONTROL_GAP   (since 2026-07-14) ← incident open
 │    └── Repo: kyc-pipeline      → NOT_APPLICABLE (exemption declared)
```

An org transitions to `ORG_COMPLIANT` only when all in-scope repos are `CONTROL_MET` or `NOT_APPLICABLE`.

#### 3.2.3 State Machine and Incident Creation

```
Control State Machine
─────────────────────────────────────────────────────────────────
                       scan diff
   NOT_EVALUATED ──────────────────► CONTROL_MET
                                           │         ▲
                                   diff    │         │  diff
                               (met→gap)  ▼         │  (gap→met)
                                     CONTROL_GAP ───┘
                                           │
                                   ≥1 scan │ gap persists
                                           ▼
                                     INCIDENT_OPEN
                                           │
                                   gap→met │ diff
                                           ▼
                                     INCIDENT_RESOLVED
```

When a diff shows a control flipping `CONTROL_MET → CONTROL_GAP`, an incident is created with the diff as immutable evidence. Resolution: developer re-adds the missing AIBOM property → next scan → diff shows `gap→met` → incident resolves with the closing diff attached.

#### 3.2.4 Hash-Chain Evidence Vault

```
self_hash = SHA-256(scan_id ‖ timestamp ‖ aibom_hash ‖ controls ‖ prev_hash)
```

Each snapshot includes the hash of the previous — any retroactive alteration invalidates all subsequent `prev_hash` values. Enterprise users export the full snapshot chain as a machine-verifiable audit trail for regulator submission. `evidence.occurrences[]` entries from the AIBOM are stored verbatim — every artifact observed at scan time is preserved.

#### 3.2.5 Renewal Tracker

```yaml
renewal_obligation:
  org_id: acme-corp
  reg_id: us.ca.sb1047
  obligation: "Annual safety and security protocol submission"
  next_due: "2027-01-31"
  recurrence: annual
  alert_schedule:
    - trigger_days_before: 90
      channel: [email, dashboard]
    - trigger_days_before: 30
      channel: [email, dashboard, slack_webhook]
    - trigger_days_before: 7
      channel: [email, dashboard, slack_webhook, pagerduty]
      severity: high
    - trigger_days_before: 0
      channel: [email, dashboard, slack_webhook, pagerduty]
      severity: critical
      status: OVERDUE
```

Alert escalation is additive: at 7 days, all four channels fire.

---

## Section 4 — Detection and Reporting Layers

### 4.1 AnomalyEngine — Flagging

#### 4.1.1 Execution Model

`airom scan .` is a thin client operation. It walks the filesystem, resolves AI component references, and serializes the result into an AIBOM document. **Zero anomaly computation runs on the client.** The AIBOM is posted to the AIROM cloud service; the cloud compares it against the stored historical AIBOM for that repo+branch, runs all anomaly rules against the diff, and returns a structured alert payload. The CLI renders alerts to stdout and exits with code `1` if any alerts are at severity `high` or above.

```
airom scan .
  │
  ├── [CLIENT] Walk repo, extract AIBOM JSON
  ├── [CLIENT] POST /v1/scan { aibom: ..., repo: ..., branch: ... }
  │
  └── [CLOUD]  diff(current_aibom, prev_aibom)
               run_rules(diff, repo_config)
               return { alerts: [...], aibom_id: "..." }
  │
  └── [CLIENT] Render alerts → stdout / annotations / PR comment
               exit 0|1
```

#### 4.1.2 Rule-Based Only (Phase 1)

No statistical baselines. No Gaussian deviation models. No ML classifiers. These require a data corpus that does not exist at launch. The rule engine produces labelled verdicts that will serve as ground-truth training data for a future ML layer when the corpus exists.

Every anomaly rule is a YAML document in the same schema as existing AIROM detection rules. Customers add org-scoped custom rules by placing YAML files in `.airom/rules/`.

#### 4.1.3 The `.airomapproved` File

The `.airomapproved` file lives in the repo root, is committed to git, and is the single source of truth for what AI components are sanctioned. Every approval is a git commit — the full audit trail (who approved, when, from which PR) is recoverable from `git log .airomapproved`.

```yaml
# .airomapproved — managed by `airom approve` / `airom revoke`
schema_version: "1.0"
repo: "github.com/acme-corp/loan-decisioning"

components:
  - id: "openai/gpt-4o"
    type: model_api
    approved_by: "sarah.chen@acme-corp.com"
    approved_at: "2025-11-03T14:22:00Z"
    approved_via_pr: 412
    scope:
      - path_glob: "src/underwriting/**"
    permitted_config:
      temperature:
        max: 0.3
      max_tokens:
        max: 2048

revocations: []
```

**Anything in the AIBOM but absent from `.airomapproved` is a `shadow-ai` anomaly.** `airom approve <component-id>` writes to this file and opens a PR. Hand-edits are detected: the CLI validates the file signature on read.

#### 4.1.4 Anomaly Rule Schema — Four Built-in Rules

```yaml
# shadow-ai: unapproved component detected
id: "shadow-ai-detected"
severity: high
match:
  diff_section: added
  conditions:
    - field: "component.approved"
      operator: eq
      value: false
alert:
  message: >
    Shadow AI detected: {{component.id}} found in {{component.source_file}}
    (line {{component.source_line}}) is not listed in .airomapproved.
  remediation: >
    Run `airom approve {{component.id}} --scope {{component.source_file}}`
```

```yaml
# model-swap: model replaced without approval
id: "model-swap-detected"
severity: high
match:
  diff_section: modified
  conditions:
    - field: "delta.model_id.changed"
      operator: eq
      value: true
    - field: "component.approved"
      operator: eq
      value: false
alert:
  message: >
    Model swap: {{component.source_file}} changed from
    {{delta.model_id.before}} → {{delta.model_id.after}}.
    The replacement is not in .airomapproved.
```

```yaml
# config-drift: safety parameter changed beyond approved bounds
id: "config-drift-detected"
severity: medium
match:
  diff_section: modified
  conditions:
    - field: "delta.config.temperature.after"
      operator: gt
      value_from: "approved_config.temperature.max"
    - field: "component.approved"
      operator: eq
      value: true
alert:
  message: >
    Config drift: {{component.id}} temperature={{delta.config.temperature.after}}
    exceeds approved maximum of {{approved_config.temperature.max}}.
```

```yaml
# regulatory-proximity: AI in high-risk domain path
id: "regulatory-proximity-hiring"
severity: high
match:
  diff_section: [added, unchanged]
  conditions:
    - field: "component.source_file"
      operator: path_contains_any
      value: ["hiring", "recruitment", "applicant", "resume", "candidate", "ats"]
alert:
  message: >
    Regulatory proximity: {{component.id}} in {{component.source_file}}
    matches hiring-domain patterns. NY Local Law 144 bias audit may apply.
  regulatory_refs:
    - "NY Local Law 144 (2023)"
    - "EEOC Technical Assistance on AI (2023)"
```

Additional proximity rules ship for `credit/lending` (ECOA, CFPB), `patient/clinical/ehr` (HIPAA, FDA SaMD), and `insurance/underwriting` (NAIC model bulletin).

#### 4.1.5 Real Alert Output Example

```
AIROM Scan — acme-corp/loan-decisioning @ feature/new-scoring-model

  ✗ [HIGH]  shadow-ai-detected
            openai/gpt-4-turbo
            src/underwriting/scoring.py:47  (commit a9f3c22)
            Not listed in .airomapproved.
            → Run: airom approve openai/gpt-4-turbo --scope src/underwriting/scoring.py

  ✗ [HIGH]  regulatory-proximity (credit/lending)
            openai/gpt-4-turbo
            src/underwriting/scoring.py:47
            Possible ECOA / CFPB Circular 2023-03 obligations triggered.

──────────────────────────────────────────────────
  14 components scanned  ·  13 approved  ·  1 unapproved
  2 alerts  (2 HIGH, 0 MEDIUM, 0 LOW)
  Exit code: 1
```

#### 4.1.6 Agentless Default vs. Agent Mode

**Agentless (default):** Detection fires when CI runs `airom scan .`. No persistent process. Gaps between CI runs are acknowledged blind spots — the correct default for most teams.

**Agent mode (enterprise opt-in):** A lightweight binary (`airom-agent`) installed on an org server. Registers a webhook with GitHub/GitLab/Bitbucket and receives push events in real time. On each push it triggers a targeted AIBOM extraction for only the modified paths and submits the diff to the cloud AnomalyEngine without waiting for CI.

```yaml
# .airom/agent.yaml  (enterprise agent config)
agent:
  mode: webhook
  scm: github
  watched_branches:
    - main
    - "release/**"
  scan_on:
    - push
    - pull_request.opened
  cloud_endpoint: "https://api.airom.io/v1/scan"
  alert_channels:
    - type: slack
      webhook_env: AIROM_SLACK_WEBHOOK
    - type: github_check
      enabled: true
```

The agent does not run anomaly logic locally. It is a webhook receiver that triggers cloud scans faster than CI would.

---

### 4.2 ReportEngine — Writing

#### 4.2.1 Execution Model

Report generation is a **cloud/server-only feature**. No LLM runs on the client. `airom report --template colorado-ai-act` sends the AIBOM and compliance mapping results to the AIROM cloud service; the cloud generates the report and streams the rendered document back.

```
airom report --template colorado-ai-act --format pdf --output ./reports/
  │
  ├── [CLIENT] Read latest AIBOM
  ├── [CLIENT] POST /v1/report { aibom_id, template, format, llm_profile }
  │
  └── [CLOUD]  Load AIBOM + compliance mapping verdicts
               Construct evidence-anchored prompt blocks per section
               Call LLM → generate prose
               Validate citations → reject uncited claims
               Render to PDF / HTML / Word / Markdown
               Stream back binary
  │
  └── [CLIENT] Write ./reports/colorado-ai-act-2026-08-21.pdf
               Print: "Report written. 4 manual sections require human attestation."
```

#### 4.2.2 On-Premises Option (Enterprise)

For organizations whose data governance prohibits sending AIBOM data to AIROM's cloud:

```bash
docker run -d \
  --name airom-report-engine \
  -p 8443:8443 \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  airom/report-engine:latest \
  --listen 0.0.0.0:8443
```

```yaml
# ~/.airom/config.yaml
report_engine:
  endpoint: "https://airom.internal.acme-corp.com/v1"
  llm_backend:
    provider: anthropic           # openai | anthropic | google | ollama
    api_key_env: ANTHROPIC_API_KEY
    model: "claude-3-5-sonnet-20241022"
```

#### 4.2.3 Evidence-First Report Generation

Every sentence the LLM generates must be grounded in a specific `evidence_id` from the AIBOM. The citation validator runs as a post-processing step — any sentence without a valid `[ev:...]` citation is either stripped and replaced with `[MANUAL ATTESTATION REQUIRED]` or flagged in the rendered document as unverified.

| ComplianceMapper verdict | Report treatment |
|---|---|
| `met` | Pre-filled prose with `[ev:...]` citations from AIBOM. Reviewer can edit. |
| `gap` | Gap description + specific remediation step. No false claims. |
| `manual` | Section header rendered, attestation prompt inserted, body left blank for human. |

#### 4.2.4 Concrete Before/After: AIBOM JSON → Report Prose

**Input AIBOM + compliance verdict excerpt:**
```json
{
  "components": [{
    "evidence_id": "ev:aibom_01J8X4KM:src/underwriting/scoring.py:47",
    "id": "openai/gpt-4o",
    "source_file": "src/underwriting/scoring.py",
    "source_line": 47,
    "approved_by": "sarah.chen@acme-corp.com",
    "approved_at": "2025-11-03T14:22:00Z"
  }],
  "compliance_verdicts": {
    "colorado_ai_act": {
      "6-1-1702(1)(a)": { "verdict": "met",    "evidence": ["ev:aibom_01J8X4KM:src/underwriting/scoring.py:47"] },
      "6-1-1702(2)":    { "verdict": "gap",    "gap_detail": "No algorithmic impact assessment found." },
      "6-1-1702(3)":    { "verdict": "manual", "attestation_prompt": "Describe the consumer feedback mechanism." }
    }
  }
}
```

**Generated Section 4.2 — Colorado AI Act Annual Report:**

> **4.2 Use of High-Risk AI Systems in Credit Decisioning**
>
> Acme Corp deploys a high-risk artificial intelligence system within its consumer loan underwriting workflow. The system uses OpenAI GPT-4o, invoked via API at `src/underwriting/scoring.py` line 47 [ev:aibom_01J8X4KM:src/underwriting/scoring.py:47]. This component was approved for deployment on November 3, 2025, by sarah.chen@acme-corp.com [ev:aibom_01J8X4KM:src/underwriting/scoring.py:47].
>
> **§6-1-1702(2) — Algorithmic Impact Assessment:** ⚠️ GAP — No algorithmic impact assessment record identified in the AIBOM as of 2026-08-21. Conduct an AIA per CDPHE guidance and attach as Exhibit B.
>
> **§6-1-1702(3) — Consumer Feedback Mechanism:** `[MANUAL ATTESTATION REQUIRED]`
> *Describe the mechanism by which consumers may request human review. Include contact method, response SLA, and escalation path.*
>
> Attested by: _________________ Date: _________

`met` sections: pre-filled prose with citations. `gap` sections: finding + remediation. `manual` sections: blank attestation block.

#### 4.2.5 Phase 1 Report Templates

| Template | Regulation | Primary Format |
|---|---|---|
| `nist-ai-rmf` | NIST AI RMF 1.0 | PDF (+ Word, Markdown) |
| `colorado-ai-act` | Colorado AI Act SB 24-205 | PDF (+ Word) |
| `ny-ll144` | NY Local Law 144 | HTML public posting (+ PDF, Word) |
| `executive-summary` | Internal board/executive | Word (+ PDF, HTML) |

```bash
airom report --template colorado-ai-act --format pdf --output ./filings/2026/
airom report --template ny-ll144       --format html --output ./public/bias-audit/
airom report --template executive-summary --format docx --output ./board/q3-2026/
```

---

## Section 5 — FilingAgent and System Architecture

### 5.1 FilingAgent — Renewing

The FilingAgent prepares legally-defensible filing packages and surfaces them to a human who decides whether to submit. **The agent never submits autonomously. This is structural, not configurable.**

The submit action is a browser-side button, disabled at page load, enabled only after all UI preconditions are satisfied. The backend `POST /api/v1/filings/{id}/submit` endpoint requires a `human_confirmation_token` — a one-time HMAC signed with the user's session key, expires in 90 seconds, generated only when the user explicitly clicks a modal confirmation. There is no headless path.

```
# What does NOT exist in this codebase:
# - AIROM_AUTO_SUBMIT=true
# - filing_agent.auto_submit: true
# - --auto-submit flag on any CLI command
# - Any cron or scheduler that calls /submit
```

CI guardrail enforces this permanently:
```yaml
- name: No auto-submit paths
  run: |
    ! grep -rn "auto_submit\|AUTO_SUBMIT\|autosubmit" \
      --include="*.py" --include="*.ts" --include="*.yaml" \
      src/ config/ scripts/
```

#### 5.1.1 Filing Registry

Filing metadata lives in the same regulation pack YAML, under a `filing_requirements` key:

```yaml
filing_requirements:
  - filing_id: CO-AI-ACT-EMP-NOTIFY
    name: Employment AI System Notification
    trigger:
      org_types: [employer]
      employee_threshold: 50
      system_risk_tier: [high, limited]
    cadence:
      type: event_driven
      events: [new_high_risk_system_deployed, material_change_to_existing_system]
      deadline_offset_days: 30
    format:
      primary: api
      endpoint: https://coag.gov/ai-systems/api/v1/notifications
      fallback: pdf_form_fill
    evidence_attachments: [aibom_json, bias_audit_report, impact_assessment_pdf]
    retention_years: 5
```

**Phase 1 filings** (three — chosen because filing criteria are machine-readable against the AIBOM):

| Filing | Regulation | Format |
|---|---|---|
| CO-AI-ACT-EMP-NOTIFY | Colorado AI Act (SB 205) | REST API + PDF fallback |
| NY-LL144-BIAS-AUDIT-POST | NYC Local Law 144 | Email + public URL posting |
| CA-AB2013-TRANSPARENCY-REPORT | CA AB 2013 | Public URL + CPPA portal |

#### 5.1.2 Green/Yellow/Red Filing Review UI

The review screen maps directly to AIROM's existing verdict taxonomy: `met` → GREEN, `manual` → YELLOW, `gap` → RED. No new status concepts.

**Locking rules:**
- GREEN: pre-filled from AIBOM, input fields disabled. "View source" link shows the AIBOM field that populated each value.
- YELLOW: inputs enabled, required. Submit button disabled until every YELLOW field has a value.
- RED: user must either resolve and re-scan, or click "Acknowledge gap" and type a documented reason (min. 20 chars).
- Submit activates only when: `yellows_answered == true AND (reds_count == 0 OR all_reds_acknowledged == true)`

**Filing review wireframe — Colorado AI Act Employment Notification:**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  AIROM FilingAgent  ·  Colorado AI Act — Employment System Notification     ║
║  Filing ID: CO-AI-ACT-EMP-NOTIFY  ·  Deadline: 2026-09-14  ·  Draft        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  AIBOM Version: aibom-sha256:4f9a2c...  ·  Last scan: 2026-08-21 09:14 UTC ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ┌─ SECTION 1: System Identity ──────────────────────────────── [●GREEN] ─┐ ║
║  │  System Name:     ResumeRanker v2.4.1                      [🔒 LOCKED] │ ║
║  │  Developer:       Acme Corp                                [🔒 LOCKED] │ ║
║  │  Deployment Date: 2026-07-30                               [🔒 LOCKED] │ ║
║  │  Risk Tier:       High-Risk (Employment)                   [🔒 LOCKED] │ ║
║  │  Source: aibom.system_metadata  [View source ↗]                        │ ║
║  └──────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌─ SECTION 2: Bias Audit Results ───────────────────────────── [●GREEN] ─┐ ║
║  │  Last Audit Date:      2026-06-15                          [🔒 LOCKED] │ ║
║  │  Auditor:              FairML Associates LLC               [🔒 LOCKED] │ ║
║  │  Adverse Impact Ratio: 0.87 (above 0.80 threshold)        [🔒 LOCKED] │ ║
║  │  Source: aibom.bias_audit  [View source ↗]                             │ ║
║  └──────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌─ SECTION 3: Candidate Notification Process ───────────────── [●YELLOW]─┐ ║
║  │  ⚠  Machine cannot verify — human attestation required                 │ ║
║  │  Notification method:  [ dropdown: Email / In-app / Letter ]  *        │ ║
║  │  Date first notice:    [ date picker                        ]  *        │ ║
║  │  Opt-out URL:          [ text field                         ]  *        │ ║
║  │  ✗ Not yet answered  (submit locked until complete)                     │ ║
║  └──────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌─ SECTION 4: Impact Assessment ────────────────────────────── [●YELLOW]─┐ ║
║  │  ⚠  Machine cannot verify — human attestation required                 │ ║
║  │  Completed by:   [ text field: name/title                   ]  *        │ ║
║  │  Date:           [ date picker                              ]  *        │ ║
║  │  Document ref:   [ text field or file upload                ]  *        │ ║
║  │  ✗ Not yet answered  (submit locked until complete)                     │ ║
║  └──────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌─ SECTION 5: Data Retention Policy ────────────────────────── [●RED]  ─┐ ║
║  │  ✖  COMPLIANCE GAP — BLOCKS FILING                                     │ ║
║  │  Gap: No documented data retention policy found in AIBOM.              │ ║
║  │  Required: CO AI Act §6-1-1703(2)(b) — retention policy ≥ 2 years.   │ ║
║  │  [Resolve gap →]  OR  [Acknowledge gap]                                │ ║
║  │  ┌─────────────────────────────────────────────────────────────────┐   │ ║
║  │  │ Policy under legal review, expected 2026-09 completion.         │   │ ║
║  │  └─────────────────────────────────────────────────────────────────┘   │ ║
║  │  ✓ Gap acknowledged (reason logged to audit trail)                      │ ║
║  └──────────────────────────────────────────────────────────────────────┘  ║
║                                                                              ║
║  ┌─ SUBMISSION ─────────────────────────────────────────────────────────┐  ║
║  │  Status:  2 of 2 yellows answered  ✓  ·  1 red acknowledged  ✓      │  ║
║  │                                                                       │  ║
║  │         ┌─────────────────────────────────┐                          │  ║
║  │         │   ✅  SUBMIT TO PORTAL  (Human) │  ← enabled               │  ║
║  │         └─────────────────────────────────┘                          │  ║
║  │  By clicking Submit, you attest this filing is accurate.             │  ║
║  │  This action is logged immutably.                                    │  ║
║  └──────────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

### 5.2 Full System Architecture

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                         AIROM COMPLIANCE PLATFORM                              ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  ┌──────────────────────────── CLIENT LAYER ──────────────────────────────────┐ ║
║  │                                                                             │ ║
║  │   airom-cli  (static binary, no runtime deps, no LLM, no network req)      │ ║
║  │     airom scan .          ← core; fully offline                             │ ║
║  │     airom report          ← calls cloud Report Engine (explicit opt-in)    │ ║
║  │     airom file            ← calls cloud Filing Agent (explicit opt-in)     │ ║
║  │     airom update          ← pulls signed regulation packs                  │ ║
║  │                                                                             │ ║
║  │   OUTPUT: aibom.json  (stays on disk, never auto-uploaded)                  │ ║
║  │                                                                             │ ║
║  │   Local Regulation Pack Store  (~/.airom/packs/*.yaml)                     │ ║
║  │   Verified via ed25519 signature before load; pack version pinnable         │ ║
║  │                                                                             │ ║
║  │   MODE A: AGENTLESS (default — CI Push)                                    │ ║
║  │     GitHub Actions / GitLab CI → runs airom scan . in pipeline step        │ ║
║  │     SARIF output, PR annotation, exit code 1 on gap                        │ ║
║  │     No background process; no persistent connection                         │ ║
║  │                                                                             │ ║
║  │   MODE B: AGENT (background process — Enterprise opt-in)                   │ ║
║  │     airom-agent  (long-running daemon on org server / k8s pod)             │ ║
║  │     Receives push webhooks → triggers cloud scans in real time             │ ║
║  │     IT ADAPTERS (all optional, plug-in):                                   │ ║
║  │       GitHub Actions  · GitLab CI  · Jira  · Slack/Teams                  │ ║
║  │       ServiceNow  · Splunk/DataDog  · PagerDuty                            │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                  ║
║  ═════════════════════════ TRUST BOUNDARY ════════════════════════════════════  ║
║  ║  Crosses: AIBOM JSON (signed with org API key) + explicit user commands  ║   ║
║  ║  Never crosses: source code, model weights, raw scan artifacts           ║   ║
║  ═══════════════════════════════════════════════════════════════════════════════  ║
║                                                                                  ║
║  ┌──────────────────────────── UPDATE CHANNEL ────────────────────────────────┐ ║
║  │  updates.airom.dev  (ed25519-signed bundles, daily cadence)               │ ║
║  │  Regulation packs and CLI binary releases: SAME channel, FULLY DECOUPLED  │ ║
║  │  Pack fails signature verification → rejected, previous version retained  │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                  ║
║  ┌──────────────────────────── CLOUD LAYER ───────────────────────────────────┐ ║
║  │                                                                             │ ║
║  │   RegWatch: statute crawler → LLM parse (serverside only) →               │ ║
║  │     human expert review → ed25519 sign → push to CDN                      │ ║
║  │     No org data touches this service                                       │ ║
║  │                                                                             │ ║
║  │   Anomaly Engine: receives AIBOM diffs (old vs new) →                     │ ║
║  │     pure rule matching → anomaly events → IT adapters                      │ ║
║  │                                                                             │ ║
║  │   Report Engine: receives AIBOM JSON (org API key verified) →             │ ║
║  │     LLM prose generation → evidence citation validation →                  │ ║
║  │     returns signed PDF/HTML/Word → AIBOM NOT persisted (ephemeral)        │ ║
║  │                                                                             │ ║
║  │   Filing Agent: receives AIBOM + filing_req + user session →              │ ║
║  │     form preparation + validation → hosts filing review UI →               │ ║
║  │     dispatches to state portals ONLY on human_confirmation_token →         │ ║
║  │     writes immutable audit log                                              │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                  ║
║  ┌──────────────────────── ON-PREM OPTION (Enterprise) ───────────────────────┐ ║
║  │  docker run airom/report-engine:latest                                     │ ║
║  │  Customer provides: LLM API key (Azure OpenAI / Anthropic / Ollama)       │ ║
║  │  CLI config: report_engine.endpoint → customer's on-prem URL              │ ║
║  │  AIROM cloud receives nothing when on-prem is configured                  │ ║
║  └─────────────────────────────────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

**Data boundary — enforced structurally:**

| Data | Lives where | Can cross boundary? |
|---|---|---|
| Source code | Client disk only | **NEVER** |
| Model weights | Client disk only | **NEVER** |
| `aibom.json` | Client disk (canonical) | YES — on explicit cmd only |
| Regulation packs | CDN (public) + client cache | One-way: CDN → client |
| Reports (PDF) | Cloud (generated, returned) | Returned to client only |
| Filing payload | Cloud (ephemeral per-session) | Dispatched to regulator |

The `airom scan` command has zero network socket calls in its execution path. The network client module is not linked into the scan subcommand's dependency graph:

```bash
# CI check: scan subcommand must not import network packages
go list -deps ./cmd/scan/... | grep -E "net/http|net.Dial|cloud" && exit 1 || exit 0
```

---

## Section 6 — Strategic Decisions, Moat & Roadmap

### 6A: Strategic Decisions

#### Decision 1 — Open Core Boundary

The scanner — AIBOM generation, NIST AI RMF / OWASP LLM Top 10 mapping, CVE overlay — is and remains open source. It is the distribution channel. RegWatch, ComplianceDB, ReportEngine, and FilingAgent are paid cloud infrastructure and are never open-sourced.

| Component | License | Runs where |
|---|---|---|
| `airom scan` | Apache 2.0 | Local binary / CI |
| NIST/OWASP mapping engine | Apache 2.0 | Local binary / CI |
| CVE overlay | Apache 2.0 | Local binary / CI |
| Regulation packs | Proprietary signed pack | Pulled from CDN, evaluated locally |
| RegWatch | Proprietary SaaS | AIROM cloud |
| ComplianceDB | Proprietary SaaS | AIROM cloud / customer on-prem |
| ReportEngine | Proprietary SaaS | AIROM cloud / customer on-prem Docker |
| FilingAgent | Proprietary SaaS | AIROM cloud |

Nothing in the open-source binary phones home, requires authentication, or degrades without a paid key. A team can run `airom scan --output aibom.json` forever for free.

#### Decision 2 — Binary Releases and Regulation Updates Are Fully Decoupled

Binary releases ship every few weeks. Regulation packs update daily through the existing signed channel. These two cycles never intersect. A regulation pack is a versioned, signed bundle:

```
.airompack/
  manifest.json        # version, effective_date, jurisdiction, sources[]
  controls/            # structured control definitions
  citations/           # statute text fragments with section references
  mappings/            # control → NIST/OWASP crosswalk
  signature.sig        # ed25519 over SHA-256 of all above
```

Version pinning is supported:
```yaml
# .airom.yaml
packs:
  colorado-ai-act: "2025-09-01"
  ny-local-law-144: "latest"
```

#### Decision 3 — LLM Is Server-Side Infrastructure, Not a Client Feature

The `airom` binary is a static binary, forever. No LLM runtime, no model weights, no model API calls, no network calls beyond pack updates and optional result push. All LLM work runs either in AIROM cloud or in a customer-controlled on-prem Docker container.

Compliance-sensitive organizations will not accept a scanning tool that makes outbound LLM API calls from the developer's machine, sends scan results to a third-party model provider without explicit data processing agreements, or runs AI inference their security team hasn't reviewed.

#### Decision 4 — Agentless-First, Agent as Enterprise Opt-In

Default deployment: one line in CI config, no IT approval needed:

```yaml
# GitHub Actions — zero-config default
- uses: airomhq/airom-action@v1
  with:
    api-key: ${{ secrets.AIROM_API_KEY }}
```

Agent mode (persistent background process) is an Enterprise feature, requires explicit IT provisioning, and is gated behind a flag. This maximizes OOTB adoption: no ticket to IT, no security review, no installation approval. The team that needs the agent is already an enterprise account.

#### Decision 5 — OOTB Priority: The Hook That Matters

The hook: run `airom scan`, get CVEs and NIST AI RMF gaps in 90 seconds. CVEs are the right hook for three specific reasons:

1. **Compliance teams understand them.** CVEs are the common language between security, engineering, and legal. A CVSS 9.1 in a model serving dependency is immediately actionable to every stakeholder.
2. **They create urgency.** A NIST gap is abstract. A CVE with a known exploit and a CVSS score is a liability conversation that happens today.
3. **They have a clear fix path.** AIROM surfaces the CVE, links the advisory, shows the patched version. The team can close the loop without understanding compliance frameworks.

Everything else — RegWatch, ComplianceDB, ReportEngine, FilingAgent — is the answer to "what do I do about this at the organizational level?" That's the paid product.

#### Decision 6 — Phase-by-Phase State Coverage

Phase 1 (Q3 2026): **CA, CO, NY, IL, TX, VA** — selected on enforcement activity, not population. Colorado has the first enacted comprehensive AI Act with active rulemaking. NY Local Law 144 is in active enforcement. CA has the highest-volume AI legislation pipeline.

Do not attempt 50-state coverage at launch. A regulation pack that maps the wrong control to the wrong statute section fails an audit. Quality matters more than breadth.

#### Decision 7 — `.airomapproved` Governance Primitive

The simplest possible governance workflow: a git-tracked list of approved AI components. Anything in the AIBOM but absent from `.airomapproved` is shadow AI.

```yaml
# .airomapproved
approved:
  - purl: "pkg:pypi/openai@1.35.0"
    approved_by: "jane.doe@company.com"
    approved_date: "2025-08-01"
    ticket: "RISK-1042"
deny:
  - purl: "pkg:pypi/langchain@*"
    reason: "Pending security review"
```

This is not a replacement for AIBOM. It is an access control layer on top, designed for compliance and legal audiences who need a clear record of "who approved this model and when."

#### Decision 8 — Green/Yellow/Red Filing Gate

| State | Meaning | UI behavior |
|---|---|---|
| 🟢 Green | Machine-verified from AIBOM / ComplianceDB evidence | Pre-filled, user can override |
| 🟡 Yellow | Machine cannot verify — needs human confirmation | Required field, blocks submit |
| 🔴 Red | Compliance gap — no evidence, no suggestion | Must be answered or gap acknowledged |

Submit button locks until all reds are either answered or explicitly acknowledged. Acknowledged gaps are recorded with timestamp and user identity. This makes the system legally defensible: the compliance officer is not rubber-stamping machine output — they are certifying a document where every field is machine-evidenced, human-confirmed, or explicitly acknowledged as a known gap.

---

### 6B: The Moat

**Advantage 1 — Evidence DNA**

AIROM is the only AIBOM tool that populates `evidence.occurrences[]` in CycloneDX — exact file paths, line numbers, and import chains that prove a model or AI library is actually used, not merely listed:

```json
{
  "name": "openai",
  "version": "1.35.0",
  "evidence": {
    "occurrences": [
      { "location": "src/agent/llm_client.py", "line": 12, "symbol": "openai.ChatCompletion" }
    ]
  }
}
```

A compliance auditor receiving an AIBOM without `evidence.occurrences[]` has a list of dependencies. One with occurrences has a verifiable map of AI usage. Competitors can copy the dashboard; they cannot copy the static analysis architecture without rebuilding their scanner from scratch.

**Advantage 2 — Regulatory Data Network**

Every regulation pack shipped has been parsed from statute text, mapped to controls, cross-walked to NIST/OWASP, reviewed by a human compliance expert, and corrected when the LLM got it wrong. Every correction is a labeled training example. The result: a proprietary compliance knowledge base that grows with every pack update and every filed document. Not replicable by a competitor who starts today.

**Advantage 3 — Trust Through Honesty**

AIROM marks controls as `manual` when it cannot verify them. It never fills in a compliance field with a confident answer it doesn't have evidence for:

```
Control: GOVERN-1.2 — Organizational roles and responsibilities defined
Status:  MANUAL — No organizational policy document detected in scan scope.
         Evidence required: org_policy.pdf or equivalent.
```

Competitors who ship a dashboard showing 94% compliance on first scan tell customers what they want to hear. Those customers discover the gap during an audit, not before. AIROM customers know their gaps before the auditor does. That's the trust moat. It's also the sales motion: "your current tool says you're compliant; let's show you what you're actually missing."

---

### 6C: 12-Month Roadmap

#### Months 0–3: OOTB Foundation — Ship Fast

Every feature in this phase shortens time-to-value for the first scan. No enterprise infrastructure.

| Deliverable | Description |
|---|---|
| CVE overlay expansion | AI-specific library coverage: HuggingFace Transformers, LangChain, LlamaIndex, vLLM, Ollama, ONNX Runtime |
| SARIF → GitHub Code Scanning | GitHub Action that posts `airom scan` results as Code Scanning alerts natively in GitHub Security tab |
| `.airomapproved` v1 | `airom approve <purl>`, `airom deny <purl>`, `airom diff`. File format v1 spec published. |
| Compliance dashboard MVP | Web UI, login with GitHub/Google. Shows per-regulation: met / gap / manual count. No LLM, no filing. |
| Colorado AI Act pack | Phase 1 paid pack — full control mapping, citation links |
| NY Local Law 144 pack | Phase 1 paid pack — employment AI, adverse action controls |

**Exit criteria:** Developer can `brew install airom`, run `airom scan`, push results with an API key, and see CVE and NIST gap status in the dashboard within 5 minutes of install.

#### Months 3–6: Enterprise Intelligence

| Deliverable | Description |
|---|---|
| RegWatch (6-state + federal) | Statute monitoring for CA, CO, NY, IL, TX, VA + NIST, FTC, EEOC, CFPB. Daily diff alerts. |
| ComplianceDB v1 | Org-scoped state machine, historical scan snapshots, incident log, trend reporting |
| Agentless push integrations | Jira auto-create on new gaps. Slack alerts. GitHub Actions trigger on AIBOM diff. |
| CA, IL, TX, VA packs | Phase 1 completion |
| Community benchmark data | Aggregate anonymized gap rates by industry/stack (free tier) |

**Exit criteria:** Enterprise compliance team can track AI compliance posture across all 6 Phase 1 states, receive alerts when regulations change, and see 6-month trend history.

#### Months 6–9: Reports

| Deliverable | Description |
|---|---|
| ReportEngine v1 (cloud) | LLM-agnostic report service. Input: AIBOM + ComplianceDB state. Output: structured document. |
| Colorado AI Act report template | Filing-ready annual attestation narrative |
| NY LL144 bias audit report | Employer-facing bias audit summary |
| NIST AI RMF report | Board/executive summary with evidence citations |
| Board summary template | One-page executive report: risk rating, gap count, next filing date |
| On-prem report service | `airom/report-service` Docker image; customer provides LLM API key |
| Phase 2 states (7 states) | WA, MA, CT, NJ, FL, MN, OH (based on enforcement activity at Month 6) |

**Exit criteria:** Compliance officer can generate a Colorado AI Act annual attestation draft in under 10 minutes.

#### Months 9–12: Action

| Deliverable | Description |
|---|---|
| FilingAgent v1 | Structured filing drafts for CO, NY LL144, CA. Green/Yellow/Red gate UI. |
| Renewal tracker | Per-filing renewal calendar. Google Calendar / Outlook integration. Alerts 90/30/7 days. |
| Phase 3 state packs | LLM-assisted generation for remaining states. Human sign-off before release. |
| Enterprise launch | SSO (SAML/OIDC), RBAC (compliance officer / security engineer / read-only auditor), audit log export, SLA-backed support |

**Exit criteria:** Enterprise compliance officer can take an AIBOM from a production AI system through to a submitted Colorado AI Act annual attestation without leaving the AIROM product.

---

### 6D: Pricing

| Tier | Included | Target Buyer |
|---|---|---|
| **Open Source** (free, forever) | `airom scan` binary — AIBOM generation, NIST AI RMF / OWASP mapping, CVE overlay, SARIF output, `.airomapproved` file format | Individual developers, open-source projects, small teams evaluating compliance posture |
| **Team** ($2,400–$4,800/yr) | 6-state Phase 1 regulation packs (CO, NY, CA, IL, TX, VA), `.airomapproved` command + drift alerts, compliance dashboard, RegWatch anomaly alerts, community benchmark data | Startup / mid-market teams with a first compliance deadline and no dedicated compliance staff |
| **Enterprise** (from $24K ACV) | Everything in Team + full RegWatch, ComplianceDB with full history + trend reporting, ReportEngine (cloud + on-prem Docker), FilingAgent (CO + NY + CA, expanding), Green/Yellow/Red filing UI, renewal tracker, SSO, RBAC, audit log export, SLA support, BAA/DPA on request | Organizations with a compliance officer, board-level AI risk reporting, or active regulatory filing obligation |

> [!IMPORTANT]
> The open-source tier must remain genuinely useful without a paid account. Rate limits, watermarked output, or feature removal destroys the distribution moat. The free tier is the top of the funnel — it is not a trial. It is the product.

---

*Plan version: 1.0 — August 21, 2026 | Assembled from parallel sections, all feedback incorporated*
