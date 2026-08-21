# AIROM Compliance Platform — Master Project Management Plan

> **Objective:** Deliver the AI-Native Compliance Platform across 7 parallel engineering and operational tracks over 12 months, launching OOTB Foundation in Month 3 and full Enterprise Autonomous Compliance by Month 12.

---

## 1. Project Governance & Operating Cadence

- **Sprint Cadence:** 2-Week Sprints (26 Sprints across 4 Quarters / 12 Months).
- **Architecture Reviews:** Bi-weekly boundary & security invariant enforcement.
- **Regulatory Gate Reviews:** Weekly review of newly published state AI rules and regulation pack sign-offs.
- **Release Cycles:**
  - **Core Scanner CLI:** Monthly minor releases (v0.4.x -> v1.0.0).
  - **Regulation Packs:** Daily / On-Demand CDN releases (decoupled from binary).
  - **Cloud Services (RegWatch, ComplianceDB, ReportEngine, FilingAgent):** Continuous Deployment (CD).

---

## 2. Work Breakdown Structure (7 Work Fronts / Tracks)

`
AIROM Compliance Platform
├── [Track 1] Core Scanner & Developer CLI (Go, Local Invariants, OOTB Hook)
├── [Track 2] RegWatch & Regulatory Intelligence (Statute Crawlers, LLM Normalizer, Expert Gate)
├── [Track 3] ComplianceDB & Evidence Vault (Multi-Repo State Machine, Hash-Chained Ledger)
├── [Track 4] AnomalyEngine & Policy-As-Code (Diff Engine, .airomapproved, Shadow AI Alerts)
├── [Track 5] ReportEngine & Evidence Grounding (Server-Side LLM Writer, AST Verifier, On-Prem)
├── [Track 6] FilingAgent & Human Gate (State Form Adapters, Green/Yellow/Red UI, Audit Trail)
└── [Track 7] Enterprise GTM, Security & Compliance (Pricing, SSO/RBAC, SOC 2, HIPAA BAA)
`

---

## 3. Cross-Functional RACI Matrix

| Work Front | Core Lead | Security / SecOps | Legal & Compliance Expert | Product / GTM |
|---|---|---|---|---|
| **Track 1: Core Scanner & CLI** | **Accountable (Lead Go Eng)** | Consulted (Fuzzing/Invariants) | Informed | Consulted (Developer UX) |
| **Track 2: RegWatch & Packs** | **Accountable (Data/ML Eng)** | Consulted (ed25519 Signing) | **Responsible (Expert Gate Sign-off)** | Consulted (State priorities) |
| **Track 3: ComplianceDB** | **Accountable (Backend Eng)** | Responsible (Hash-Chain Verif) | Consulted (Audit Retentions) | Informed |
| **Track 4: AnomalyEngine** | **Accountable (Backend Eng)** | Responsible (Shadow AI policies) | Consulted (Proximity triggers) | Informed |
| **Track 5: ReportEngine** | **Accountable (Fullstack Eng)** | Responsible (Data Boundaries) | **Responsible (Statute Veracity)** | Consulted (Template layouts) |
| **Track 6: FilingAgent** | **Accountable (Fullstack Eng)** | Responsible (HMAC Auth / Token) | **Responsible (Filing Accuracy)** | Consulted (State Portal Integrations) |
| **Track 7: GTM & Enterprise** | **Accountable (Founders/GTM)** | Responsible (SOC 2, Pentests) | Responsible (MSA, DPA, BAA) | **Accountable (Sales & Pilots)** |

---

## 4. Critical Path & Dependency Flow

`
[M0-M1] Track 1: .airomapproved & CVE expansion ────────┐
[M0-M2] Track 2: CO & NY Regulation Packs ───────────────┼──> [M3 MILESTONE: OOTB Launch]
[M1-M3] Track 4: Cloud Rule-based Anomaly Diff ──────────┘          │
                                                                   ▼
[M3-M5] Track 3: ComplianceDB Multi-Repo State Engine ───┐
[M3-M6] Track 2: RegWatch Continuous Statute Crawlers ───┼──> [M6 MILESTONE: Enterprise Intel]
[M4-M6] Track 7: Web Compliance Dashboard & API Keys ────┘          │
                                                                   ▼
[M6-M8] Track 5: ReportEngine LLM Writer & AST Verifier ─┐
[M7-M9] Track 5: On-Prem Docker BYOK Container ──────────┼──> [M9 MILESTONE: Audit Reports]
[M7-M9] Track 2: Phase 2 State Expansion (7 States) ─────┘          │
                                                                   ▼
[M9-M11] Track 6: FilingAgent Green/Yellow/Red UI ───────┐
[M10-M12] Track 6: State Portal Connectors & HMAC Gate ──┼──> [M12 MILESTONE: Autonomous Compliance GA]
[M10-M12] Track 7: SOC 2 Type II & Enterprise Pricing ───┘
`

---

## 5. Risk Registry & Mitigation Playbook

| Risk ID | Description | Severity | Likelihood | Mitigation Strategy |
|---|---|---|---|---|
| **RSK-01** | LLM misinterprets an ambiguous state statute requirement | **High** | Medium | Mandatory **Human Compliance Expert Gate** before signing any regulation pack. 0% automated auto-publish for Phase 1. |
| **RSK-02** | Customer fears source code leakage to cloud | **Critical** | Low | Structural isolation: Scanner binary compiled with 0 network calls on scan. CI checks verify no network imports in scan package. |
| **RSK-03** | Erroneous autonomous submission creates regulatory liability | **Critical** | Low | Hardcoded architectural lock: 90s HMAC human confirmation token required for submit endpoint. CI rejects any uto_submit flags. |
| **RSK-04** | State regulatory portals lack REST APIs for digital filing | **Medium** | High | Multi-adapter strategy: Primary = REST API, Secondary = Form-fillable PDF with download + proof, Tertiary = Encrypted email dispatch. |
| **RSK-05** | High rate of false positives on Shadow AI detection | **Medium** | Medium | Path-scoped allowlists in .airomapproved + test scope ignore heuristics (	estdata/, 	ests/ excluded by default). |
