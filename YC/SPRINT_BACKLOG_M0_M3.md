# AIROM Compliance Platform — Sprint Backlog (Months 0–3 Foundation)

> **Sprint Cadence:** 6 Two-Week Sprints to launch the OOTB Foundation, CVE expansion, .airomapproved governance, and Phase 1 state packs.

---

## Sprint Schedule

| Sprint | Dates | Milestone Focus |
|---|---|---|
| **Sprint 1** | Weeks 1–2 | Project Setup, .airomapproved file schema, Regulation Pack Schema v1. |
| **Sprint 2** | Weeks 3–4 | irom approve/revoke CLI commands, Colorado AI Act Pack drafting. |
| **Sprint 3** | Weeks 5–6 | OSV.dev CVE overlay expansion (20+ libraries), NY LL144 Pack drafting. |
| **Sprint 4** | Weeks 7–8 | Cloud Rule-Based Diff Engine (Shadow AI alerts), Webhook ingestion MVP. |
| **Sprint 5** | Weeks 9–10 | GitHub Action (irom-action@v1) with SARIF PR security integration. |
| **Sprint 6** | Weeks 11–12 | Compliance Dashboard MVP (Met/Gap/Manual), Phase 1 Paid Pack launch. |

---

## Sprint 1 & 2 Task Breakdown (Immediate Action Items)

- [ ] **T1-01:** Implement .airomapproved parser and validator in Go (internal/approved/).
- [ ] **T1-02:** Add CLI subcommand irom approve <purl> with --scope flag.
- [ ] **T2-01:** Author Colorado AI Act regulation YAML (
ules/regulations/us-co-ai-act.yaml).
- [ ] **T2-02:** Add ed25519 signature verification utility for external regulation packs.
- [ ] **T4-01:** Implement cloud AIBOM diff calculator comparing two CycloneDX snapshots.
- [ ] **T7-01:** Deploy landing page and documentation updates for AIROM Compliance Platform.
