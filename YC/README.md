# AIROM Compliance Platform - YC Project Hub

AI-native compliance software that watches regulations across all 50 US states, flags anomalies, enables renewal filings, and writes audit reports. Replacing 80% of compliance grunt work.

Methodology: Garry Tan's gstack framework applied for product interrogation, engineering review, security audit, and sprint planning.

---

## Research & Intelligence (Phase 1 - Deep Research)

| Document | Description |
|---|---|
| [RESEARCH_COMPETITIVE_INTELLIGENCE.md](./RESEARCH_COMPETITIVE_INTELLIGENCE.md) | Competitive landscape: Credo AI, Holistic AI, Vanta, Drata, Wiz, OneTrust, ServiceNow. Pricing, moats, gaps. |
| [RESEARCH_REGULATORY_MAPPING.md](./RESEARCH_REGULATORY_MAPPING.md) | Statute-by-statute mapping: CO SB 24-205, NYC LL144, CA AB 2013, IL BIPA, TX TRAIGA, VA VCDPA. SB 1047 VETOED. |
| [RESEARCH_CODEBASE_EXTENSION_MAP.md](./RESEARCH_CODEBASE_EXTENSION_MAP.md) | AIROM Go codebase extension points: CLI registration, assembler injection, compliance engine, writer pipeline, SDK interfaces. |

## gstack Product Assessment

| Document | Description |
|---|---|
| [GSTACK_ASSESSMENT_AND_OFFICE_HOURS.md](./GSTACK_ASSESSMENT_AND_OFFICE_HOURS.md) | YC Office Hours: 6 Forcing Questions, 4 Scope Modes, 10-Star Product Vision, Magical Developer Moment. |
| [GSTACK_EXECUTABLE_PRD.md](./GSTACK_EXECUTABLE_PRD.md) | Executable PRD: System spec, invariants, data models, STRIDE threat model, acceptance criteria. |
| [GSTACK_GRANULAR_TASK_WORK_BREAKDOWN.md](./GSTACK_GRANULAR_TASK_WORK_BREAKDOWN.md) | Granular task backlog: Engineering tickets with exact Go structs, file paths, interfaces, and unit tests. |
| [GSTACK_SPRINT_METHODOLOGY.md](./GSTACK_SPRINT_METHODOLOGY.md) | Sprint methodology: 8 quality gates, Go CLI test adaptations, 2-week ceremony calendar, feature lifecycle checklist. |

## Implementation Plans

| Document | Description |
|---|---|
| [SPRINT_PLAN_RIGID.md](./SPRINT_PLAN_RIGID.md) | Rigid Sprint Plan: Research-backed, task-by-task implementation plan with exact file paths and acceptance criteria. Incorporates regulatory corrections (SB 1047 veto, no state portals). |
| [SPRINT_BACKLOG_M0_M3.md](./SPRINT_BACKLOG_M0_M3.md) | Sprint Backlog (Sprints 1-6): Immediate task breakdowns for Month 0-3 OOTB Foundation release. |

## Strategic and Architecture Documents

| Document | Description |
|---|---|
| [01_EXECUTIVE_PITCH_AND_VISION.md](./01_EXECUTIVE_PITCH_AND_VISION.md) | YC Pitch: Problem, Solution, Why Now, Market ($39B to $78B), Business Model, Moats. |
| [02_ARCHITECTURE_AND_SYSTEM_DESIGN.md](./02_ARCHITECTURE_AND_SYSTEM_DESIGN.md) | 5-Layer architecture: Scanner Core, RegWatch, ComplianceDB, AnomalyEngine, ReportEngine, FilingAgent. |
| [03_PRODUCT_PLAN_AND_SPECIFICATION.md](./03_PRODUCT_PLAN_AND_SPECIFICATION.md) | Complete product plan with YAML schemas, .airomapproved specification, Green/Yellow/Red filing gate wireframes. |
| [04_ROADMAP_AND_MILESTONES.md](./04_ROADMAP_AND_MILESTONES.md) | 12-Month Execution Roadmap with exit criteria per phase. |
| [05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md](./05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md) | 50-State regulatory matrix mapped to AIBOM evidence. |

## Project Management

| Document | Description |
|---|---|
| [06_PROJECT_MANAGEMENT_MASTER_PLAN.md](./06_PROJECT_MANAGEMENT_MASTER_PLAN.md) | 7-Track WBS, 2-Week Sprint Cadence, RACI Matrix, Risk Registry, Critical Path. |

### Track Specifications

- [Track 1: Core Scanner and CLI](./tracks/TRACK_1_CORE_SCANNER_CLI.md)
- [Track 2: RegWatch and Regulatory Intelligence](./tracks/TRACK_2_REGWATCH_INTELLIGENCE.md)
- [Track 3: ComplianceDB and Evidence Vault](./tracks/TRACK_3_COMPLIANCEDB_LEDGER.md)
- [Track 4: AnomalyEngine and Policy-as-Code](./tracks/TRACK_4_ANOMALY_ENGINE.md)
- [Track 5: ReportEngine and Evidence Grounding](./tracks/TRACK_5_REPORT_ENGINE.md)
- [Track 6: FilingAgent and Human Gate](./tracks/TRACK_6_FILING_AGENT.md)
- [Track 7: Enterprise GTM and Security](./tracks/TRACK_7_GTM_SECURITY_ENTERPRISE.md)

---

## Repository

- GitHub: https://github.com/dharmik136/airom (Fork of https://github.com/airomhq/airom)
- Local: C:/Users/remoteadmin/airom
- Core: Single static Go binary (CGO_ENABLED=0), Apache 2.0 license.
