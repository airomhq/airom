# Track 3: ComplianceDB & Evidence Vault

> **Ownership:** Senior Backend / Distributed Systems Engineer  
> **Key Focus:** Org-Scoped State Machine, Time-Series Audit History, Hash-Chained Snapshots, Renewal Calendars.

---

## 1. Scope & Technical Objectives

1. **Org-Scoped Multi-Repo Hierarchy:** Aggregate compliance posture across 50+ repositories under one organization.
2. **Immutable Hash-Chained Ledger:** Mathematically tamper-evident snapshot storage (self_hash = SHA256(...)).
3. **State Machine & Incident Management:** Automatic tracking of CONTROL_MET -> CONTROL_GAP -> INCIDENT_OPEN -> INCIDENT_RESOLVED.
4. **Renewal Alert Engine:** Multi-channel notification pipeline (Email, Dashboard, Slack, PagerDuty) on 90d/30d/7d/0d schedules.

---

## 2. Sprint Backlog & Epics (Months 3–9)

### Epic T3.1: Data Model & Hash-Chain Core (Sprint 6–8)
- [ ] Design PostgreSQL schema with append-only write constraints (REVOKE UPDATE, DELETE).
- [ ] Implement SHA-256 hash-chain snapshot generator and cryptographic chain validator.
- [ ] Implement CycloneDX evidence.occurrences[] storage and query indexing.

### Epic T3.2: Multi-Repo State Aggregator (Sprint 8–10)
- [ ] Build organization-level rollup engine (all in-scope repos must meet control for ORG_COMPLIANT).
- [ ] Implement diff processor to automatically open compliance incidents on control regression.
- [ ] Exportable audit trail package (JSON-LD and cryptographic proof bundle).

### Epic T3.3: Renewal Calendar & Escalating Alert Engine (Sprint 10–13)
- [ ] Build renewal obligation calendar service linked to regulation pack filing dates.
- [ ] Integrate notification dispatchers: SendGrid (email), Slack Webhooks, PagerDuty API.
- [ ] iCal / Google Calendar / Outlook sync feed generation.

---

## 3. Definition of Done (DoD)
- Retroactive tampering with any historical snapshot is caught by validator.
- Multi-repo org status recalculation latency < 200ms for 100 repositories.
- Alert dispatch tested with 100% delivery SLA on overdue filings.
