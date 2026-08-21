# AIROM Compliance Platform — YC Project Hub

> **One-Liner:** AI-native compliance software that watches regulations across all 50 US states, flags anomalies, enables renewal filings, and writes audit reports — replacing 80% of compliance grunt work.
> 
> **Methodology:** Designed and structured using Garry Tan's gstack framework (/office-hours + /plan-ceo-review + /spec + /cso + /plan-eng-review).

---

## Master Index

### Feature PRDs (Product Requirements Documents)
| PRD | Title & Target Sprint | Focus / Package |
|---|---|---|
| [**PRD_01_AIROMAPPROVED_GOVERNANCE.md**](./prds/PRD_01_AIROMAPPROVED_GOVERNANCE.md) | **PRD 01: .airomapproved Governance** (Sprints 1-2) | Manifest parser, CLI approve/revoke/check, Assembler Shadow AI injection. |
| [**PRD_02_REGULATION_PACKS_AND_STATE_COMPLIANCE.md**](./prds/PRD_02_REGULATION_PACKS_AND_STATE_COMPLIANCE.md) | **PRD 02: State Regulation Packs** (Sprint 3) | Zero-Go-code YAML specs for Colorado AI Act (SB 24-205), NYC LL144, CA AB 2013. |
| [**PRD_03_COMPLIANCEDB_EVIDENCE_VAULT.md**](./prds/PRD_03_COMPLIANCEDB_EVIDENCE_VAULT.md) | **PRD 03: ComplianceDB Evidence Vault** (Sprint 5) | PostgreSQL append-only ledger, hash-chain snapshot trees, incident tracking. |
| [**PRD_04_ANOMALY_ENGINE_CLOUD_DIFF.md**](./prds/PRD_04_ANOMALY_ENGINE_CLOUD_DIFF.md) | **PRD 04: AnomalyEngine Cloud Diff** (Sprint 4) | Cloud semantic diff, rule-based policy engine, hiring/credit/health tripwires. |
| [**PRD_05_REPORT_ENGINE_EVIDENCE_GROUNDING.md**](./prds/PRD_05_REPORT_ENGINE_EVIDENCE_GROUNDING.md) | **PRD 05: ReportEngine Grounded Prose** (Sprints 7-8) | Server-side LLM writer, AST [ev:...] citation verifier, Typst PDF/HTML/DOCX. |
| [**PRD_06_COMPLIANCE_DOCUMENT_AGENT.md**](./prds/PRD_06_COMPLIANCE_DOCUMENT_AGENT.md) | **PRD 06: Compliance Document Gateway** (Sprint 9) | Produce-on-demand & public posting generator, Green/Yellow/Red UI, 90s HMAC gate. |

---

### Deep Research & Intelligence (Phase 1)
| Document | Description |
|---|---|
| [**RESEARCH_COMPETITIVE_INTELLIGENCE.md**](./RESEARCH_COMPETITIVE_INTELLIGENCE.md) | Competitive landscape: Credo AI, Holistic AI, Vanta, Drata, Wiz, OneTrust, ServiceNow. |
| [**RESEARCH_REGULATORY_MAPPING.md**](./RESEARCH_REGULATORY_MAPPING.md) | Statute-by-statute mapping: CO SB 24-205, NYC LL144, CA AB 2013, IL BIPA, TX, VA. CA SB 1047 VETOED. |
| [**RESEARCH_CODEBASE_EXTENSION_MAP.md**](./RESEARCH_CODEBASE_EXTENSION_MAP.md) | AIROM Go codebase extension points: CLI commands, assembler injection, compliance specs, writer pipeline. |

---

### gstack Product Assessment & Methodology
| Document | Description |
|---|---|
| [**GSTACK_ASSESSMENT_AND_OFFICE_HOURS.md**](./GSTACK_ASSESSMENT_AND_OFFICE_HOURS.md) | YC Office Hours: 6 Forcing Questions, 4 Scope Modes, 10-Star Vision, Magical Moment. |
| [**GSTACK_EXECUTABLE_PRD.md**](./GSTACK_EXECUTABLE_PRD.md) | Master System Executable PRD: Non-negotiable invariants, STRIDE threat model, data boundary. |
| [**GSTACK_GRANULAR_TASK_WORK_BREAKDOWN.md**](./GSTACK_GRANULAR_TASK_WORK_BREAKDOWN.md) | Granular task backlog: Engineering tickets with exact Go structs, interfaces, and unit tests. |
| [**GSTACK_SPRINT_METHODOLOGY.md**](./GSTACK_SPRINT_METHODOLOGY.md) | Sprint methodology: 8 quality gates, Go CLI test adaptations, ceremony calendar. |

---

### Implementation & Sprint Plans
| Document | Description |
|---|---|
| [**SPRINT_PLAN_RIGID.md**](./SPRINT_PLAN_RIGID.md) | **Definitive Rigid Sprint Plan:** Exact task breakdowns, file paths, acceptance criteria, and DoD. |
| [**SPRINT_BACKLOG_M0_M3.md**](./SPRINT_BACKLOG_M0_M3.md) | Sprint Backlog (Sprints 1-6): Immediate task breakdown for Month 0-3 Foundation release. |
| [**06_PROJECT_MANAGEMENT_MASTER_PLAN.md**](./06_PROJECT_MANAGEMENT_MASTER_PLAN.md) | 7-Track WBS, 2-Week Sprint Cadence, RACI Matrix, Risk Registry, and Critical Path. |

---

### Strategic & Architectural Foundations
| Document | Description |
|---|---|
| [**01_EXECUTIVE_PITCH_AND_VISION.md**](./01_EXECUTIVE_PITCH_AND_VISION.md) | YC Pitch: Problem, Solution, Why Now, Market (->), Business Model, Moats. |
| [**02_ARCHITECTURE_AND_SYSTEM_DESIGN.md**](./02_ARCHITECTURE_AND_SYSTEM_DESIGN.md) | Full 5-Layer technical architecture: Invariants, trust boundaries, on-prem Docker options. |
| [**03_PRODUCT_PLAN_AND_SPECIFICATION.md**](./03_PRODUCT_PLAN_AND_SPECIFICATION.md) | Master product plan with YAML schemas, .airomapproved specification, wireframes. |
| [**04_ROADMAP_AND_MILESTONES.md**](./04_ROADMAP_AND_MILESTONES.md) | 12-Month Execution Roadmap with explicit exit criteria per phase. |
| [**05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md**](./05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md) | 50-State regulatory matrix mapped to AIBOM evidence. |

---

## Local Codebase & Setup
- **GitHub Repository:** https://github.com/dharmik136/airom
- **Local Workspace:** C:\\Users\\remoteadmin\\airom
- **Core Binary:** Single static Go binary (CGO_ENABLED=0), Apache 2.0 license.
