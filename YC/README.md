# AIROM Compliance Platform — YC Project Hub (gstack Edition)

> **One-Liner:** AI-native compliance software that watches regulations across all 50 US states, flags anomalies, enables renewal filings, and writes audit reports — replacing 80% of compliance grunt work.
> 
> **Methodology:** Designed and structured using Garry Tan's gstack framework (/office-hours + /plan-ceo-review + /spec + /cso + /plan-eng-review).

---

## Master Index

### gstack Assessment & Executable PRD
| Document | Description |
|---|---|
| [**GSTACK_ASSESSMENT_AND_OFFICE_HOURS.md**](./GSTACK_ASSESSMENT_AND_OFFICE_HOURS.md) | **YC Office Hours Assessment:** 6 Forcing Questions, 4 Scope Modes, 10-Star Product Vision, and Magical Developer Moment. |
| [**GSTACK_EXECUTABLE_PRD.md**](./GSTACK_EXECUTABLE_PRD.md) | **Executable PRD:** Full system spec, invariants, data models, STRIDE threat model, and acceptance criteria. |
| [**GSTACK_GRANULAR_TASK_WORK_BREAKDOWN.md**](./GSTACK_GRANULAR_TASK_WORK_BREAKDOWN.md) | **Granular Implementation Backlog:** Task-by-task engineering tickets with exact file paths, Go structs, interfaces, and unit tests. |

---

### Strategic & Architectural Foundations
| Document | Description |
|---|---|
| [**01_EXECUTIVE_PITCH_AND_VISION.md**](./01_EXECUTIVE_PITCH_AND_VISION.md) | YC Application & Pitch narrative: Problem, Solution, Why Now, Market (->), Business Model, Moats. |
| [**02_ARCHITECTURE_AND_SYSTEM_DESIGN.md**](./02_ARCHITECTURE_AND_SYSTEM_DESIGN.md) | Full 5-Layer technical architecture: Scanner Core, RegWatch, ComplianceDB, AnomalyEngine, ReportEngine, FilingAgent. Data boundaries & invariants. |
| [**03_PRODUCT_PLAN_AND_SPECIFICATION.md**](./03_PRODUCT_PLAN_AND_SPECIFICATION.md) | Complete product plan with YAML schemas, concrete .airomapproved specification, wireframes for Green/Yellow/Red filing gates. |
| [**04_ROADMAP_AND_MILESTONES.md**](./04_ROADMAP_AND_MILESTONES.md) | 12-Month Execution Roadmap (Months 0-3, 3-6, 6-9, 9-12) with explicit exit criteria, deliverable checklists, and resource allocations. |
| [**05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md**](./05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md) | 50-State regulatory matrix (CA, CO, NY, IL, TX, VA), enforcement trends, statutory requirements mapped to AIBOM evidence. |

---

### Project Management & Engineering Tracks
| Document | Description |
|---|---|
| [**06_PROJECT_MANAGEMENT_MASTER_PLAN.md**](./06_PROJECT_MANAGEMENT_MASTER_PLAN.md) | **Master PM Plan:** 7-Track WBS, 2-Week Sprint Cadence (26 Sprints), Cross-Functional RACI Matrix, Risk Mitigation Playbook, and Critical Path Flow. |
| [**SPRINT_BACKLOG_M0_M3.md**](./SPRINT_BACKLOG_M0_M3.md) | **Sprint Backlog (Sprints 1-6):** Immediate granular task breakdowns for the Month 0-3 OOTB Foundation release. |

#### Dedicated Track Specifications
- [**Track 1: Core Scanner & CLI**](./tracks/TRACK_1_CORE_SCANNER_CLI.md)
- [**Track 2: RegWatch & Regulatory Intelligence**](./tracks/TRACK_2_REGWATCH_INTELLIGENCE.md)
- [**Track 3: ComplianceDB & Evidence Vault**](./tracks/TRACK_3_COMPLIANCEDB_LEDGER.md)
- [**Track 4: AnomalyEngine & Policy-as-Code**](./tracks/TRACK_4_ANOMALY_ENGINE.md)
- [**Track 5: ReportEngine & Evidence Grounding**](./tracks/TRACK_5_REPORT_ENGINE.md)
- [**Track 6: FilingAgent & Human Gate**](./tracks/TRACK_6_FILING_AGENT.md)
- [**Track 7: Enterprise GTM & Security**](./tracks/TRACK_7_GTM_SECURITY_ENTERPRISE.md)

---

## Local Codebase & Setup
- **GitHub Repository:** https://github.com/dharmik136/airom
- **Local Workspace:** C:\\Users\\remoteadmin\\airom
- **Core Binary:** Single static Go binary (CGO_ENABLED=0), Apache 2.0 license.
