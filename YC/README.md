# AIROM Compliance Platform — YC Project Hub

> **One-Liner:** AI-native compliance software that watches regulations across all 50 US states, flags anomalies, enables renewal filings, and writes audit reports — replacing 80% of compliance grunt work.

---

## 📁 Repository & Master Index

### 🚀 Strategic & Product Foundations
| Document | Description |
|---|---|
| [**01_EXECUTIVE_PITCH_AND_VISION.md**](./01_EXECUTIVE_PITCH_AND_VISION.md) | YC Application & Pitch narrative: Problem, Solution, Why Now, Market (→), Business Model, Moats. |
| [**02_ARCHITECTURE_AND_SYSTEM_DESIGN.md**](./02_ARCHITECTURE_AND_SYSTEM_DESIGN.md) | Full 5-Layer technical architecture: Scanner Core, RegWatch, ComplianceDB, AnomalyEngine, ReportEngine, FilingAgent. Data boundaries & invariants. |
| [**03_PRODUCT_PLAN_AND_SPECIFICATION.md**](./03_PRODUCT_PLAN_AND_SPECIFICATION.md) | Complete product plan with YAML schemas, concrete .airomapproved specification, wireframes for Green/Yellow/Red filing gates. |
| [**04_ROADMAP_AND_MILESTONES.md**](./04_ROADMAP_AND_MILESTONES.md) | 12-Month Execution Roadmap (Months 0-3, 3-6, 6-9, 9-12) with explicit exit criteria, deliverable checklists, and resource allocations. |
| [**05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md**](./05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md) | 50-State regulatory matrix (CA, CO, NY, IL, TX, VA), enforcement trends, statutory requirements mapped to AIBOM evidence. |

---

### 📊 Project Management & Engineering Tracks
| Document | Description |
|---|---|
| [**06_PROJECT_MANAGEMENT_MASTER_PLAN.md**](./06_PROJECT_MANAGEMENT_MASTER_PLAN.md) | **Master PM Plan:** 7-Track WBS, 2-Week Sprint Cadence, Cross-Functional RACI Matrix, Risk Registry, and Critical Path Dependency Graph. |
| [**SPRINT_BACKLOG_M0_M3.md**](./SPRINT_BACKLOG_M0_M3.md) | **Sprint Backlog (Sprints 1–6):** Granular task lists for Month 0–3 OOTB Foundation launch. |

#### 🛠 Dedicated Track Specifications
- [**Track 1: Core Scanner & CLI**](./tracks/TRACK_1_CORE_SCANNER_CLI.md) — AST/Rule Detectors, Invariant Enforcement, Local CVE Overlay, .airomapproved CLI Primitives.
- [**Track 2: RegWatch & Regulatory Intelligence**](./tracks/TRACK_2_REGWATCH_INTELLIGENCE.md) — 50-State Legislative Ingestion, LLM Normalizer, Human Expert Sign-off Gate, ed25519 Signed Packs.
- [**Track 3: ComplianceDB & Evidence Vault**](./tracks/TRACK_3_COMPLIANCEDB_LEDGER.md) — Org-Scoped Multi-Repo Hierarchy, Hash-Chained Snapshots, Incident Lifecycle, Renewal Calendars.
- [**Track 4: AnomalyEngine & Policy-as-Code**](./tracks/TRACK_4_ANOMALY_ENGINE.md) — Rule-Based Diff Evaluation, Shadow AI Alarms, Config Drift, High-Risk Regulatory Proximity.
- [**Track 5: ReportEngine & Evidence Grounding**](./tracks/TRACK_5_REPORT_ENGINE.md) — Zero-Hallucination LLM Prose Writer, AST Citation Verifier, Typst PDF / HTML / DOCX, On-Prem Docker.
- [**Track 6: FilingAgent & Human Gate**](./tracks/TRACK_6_FILING_AGENT.md) — State Portal Adapters (REST/PDF/Email), Green/Yellow/Red Review UI, 90s HMAC Token Safeguard.
- [**Track 7: Enterprise GTM & Security**](./tracks/TRACK_7_GTM_SECURITY_ENTERPRISE.md) — Pricing Tiers, SSO / RBAC, SOC 2 Type II, HIPAA BAA, Enterprise Sales & POC Playbook.

---

## 🛠 Local Codebase & Setup

- **GitHub Repository:** [https://github.com/dharmik136/airom](https://github.com/dharmik136/airom) (Forked from [iromhq/airom](https://github.com/airomhq/airom))
- **Local Workspace:** C:\Users\remoteadmin\airom
- **Core Binary:** Single static Go binary (CGO_ENABLED=0), Apache 2.0 license.
