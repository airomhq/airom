# Track 2: RegWatch & Regulatory Intelligence

> **Ownership:** Data / ML Systems Engineer & Legal Compliance Lead  
> **Key Focus:** 50-State Legislative Ingestion, Server-Side LLM Statute Normalization, Human Expert Sign-off Portal, ed25519 Signed Pack Delivery.

---

## 1. Scope & Technical Objectives

1. **Statute Scraping & Ingestion:** Automated crawlers monitoring LegiScan API, OpenStates, and official state legislature sites.
2. **LLM Extraction Pipeline:** Structured extraction of statutory obligations, exemptions, triggers, and penalty tiers.
3. **Mandatory Human-in-the-Loop Review Gate:** Internal compliance workbench where legal experts inspect, edit, and certify parsed rules.
4. **Signed Distribution Network:** ed25519 cryptographic pack generator and CDN delivery channel (updates.airom.dev).

---

## 2. Sprint Backlog & Epics (Months 0–9)

### Epic T2.1: Regulation Pack Specification & Validator (Sprint 1–2)
- [ ] Finalize .airom-regpack.yaml schema specification (v1.0).
- [ ] Build strict schema validator (enforces source_url, 
etrieved_at, and obligation_type).
- [ ] Build CLI tool irom dev new-regpack <jurisdiction> for pack authoring.

### Epic T2.2: Phase 1 High-Enforcement State Packs (Sprint 2–6)
- [ ] Author & certify **Colorado AI Act** (us.co.ai-act.2024.yaml) — HB24-1468 §6-1-1702/1705.
- [ ] Author & certify **NYC Local Law 144** (us.ny.nyc-ll144.yaml) — AEDT bias audit requirements.
- [ ] Author & certify **California AI Package** (us.ca.sb1047-ab2013.yaml) — Safety & training data transparency.
- [ ] Author & certify **Illinois BIPA** (us.il.bipa.yaml) & **Texas CAPAIA**.

### Epic T2.3: RegWatch Ingestion & Expert Workbench (Sprint 7–12)
- [ ] Deploy LegiScan webhook crawlers and state gazette scrapers.
- [ ] Server-side LLM extraction prompt pipeline with deterministic temperature (0.0).
- [ ] Internal web UI for legal review team to sign off on pack releases.
- [ ] Automated ed25519 signing key integration with AWS KMS / Cloud HSM.

---

## 3. Definition of Done (DoD)
- 100% of Phase 1 regulation packs carry verified source_url and explicit gap_message strings.
- 0% unsigned packs accepted by AIROM scanner client.
- Daily CDN update sync verified with zero downtime.
