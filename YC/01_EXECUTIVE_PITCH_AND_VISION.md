# AIROM Compliance Platform — Executive Pitch & Vision (YC W27 / S27)

---

## 1. Company Information

- **Company Name:** AIROM Compliance (built on open-source AIROM)
- **One-Liner:** AI-native compliance software that continuously watches regulations across all 50 US states, flags anomalies, enables renewal filings, and drafts audit reports — replacing 80% of compliance grunt work.
- **Foundational Repository:** [github.com/dharmik136/airom](https://github.com/dharmik136/airom) (Fork of [github.com/airomhq/airom](https://github.com/airomhq/airom))
- **Core Technology:** Zero-overhead, single static Go binary AIBOM scanner (CGO=0) + cloud-managed Regulatory Intelligence Network.

---

## 2. The Problem

Over 1,500 state-level AI bills were introduced in 2025 across 45 state legislatures. In 2026, companies deploying AI systems are hit by an unprecedented wave of fragmented, conflicting compliance obligations:
- **Colorado AI Act (HB24-1468):** Requires consumer disclosures, algorithmic impact assessments, and annual risk audits for high-risk AI.
- **California SB 1047 / AB 2013 / AB 3030:** Mandates AI transparency reporting, training data disclosure, and safety protocols.
- **NYC Local Law 144:** Requires mandatory annual bias audits and public postings for automated employment decision tools.
- **Illinois BIPA / Texas / Virginia:** Heavy statutory penalties for unmanaged automated decisions and biometric AI.

### The Reality Today
Companies manage this in **fragile spreadsheets**. A compliance officer manually scrapes state websites, emails developers asking what models they use (which developers often misremember or don't report), and writes 50-page PDF reports in Microsoft Word.

When a developer changes a model from \gpt-4\ to \gpt-4o\ or tweaks temperature in production, the spreadsheet is instantly obsolete. Regulators don't just ask *'Are you compliant today?'* — they ask *'Were you ever non-compliant? For how long? What triggered it? What remediation did you take?'* Spreadsheets cannot answer time-series questions.

---

## 3. The Solution

AIROM solves this from the code up:
1. **Code-Level Ground Truth:** The open-source scanner inspects source code, dependencies, and containers to generate an AI Bill of Materials (AIBOM) with exact \ile:line\ evidence occurrences.
2. **RegWatch (Regulatory Radar):** Continuously ingests 50-state statutes, extracts structured obligations via server-side LLMs + human expert validation, and pushes daily signed regulation packs to scanners.
3. **ComplianceDB (Persistent State Machine):** Hash-chains every scan into an immutable, time-series ledger to track when controls flip \met → gap\ and computes remediation durations.
4. **AnomalyEngine (Shadow AI & Drift Guard):** Compares code changes against a committed \.airomapproved\ manifest to instantly flag shadow AI, model swaps, and configuration drift in CI/CD.
5. **ReportEngine (Evidence-Grounded Prose):** Drafts regulator-ready audit reports where **every sentence links to verified code evidence** (\[ev:...]\).
6. **FilingAgent (Autonomous Prep + Human Submit):** Pre-populates state filing forms using Green/Yellow/Red validation gates. Machine fills what it knows; humans certify and click submit.

---

## 4. Why Now?

1. **Enforcement Wave Hits in 2026:** Colorado AI Act, California AI regulations, and NYC LL 144 enforcement are active. Fines reach up to ,000 per violation.
2. **Shift from Point-in-Time Audits to Continuous Monitoring:** Auditors and regulators now demand continuous proof rather than annual retrospective check-the-box reviews.
3. **Market Expansion:** AI Compliance & Governance software market is expanding from **.3B in 2026 to .9B by 2033** (CAGR ~10.5%).

---

## 5. Business Model & Pricing

| Tier | Price | Target Customer | Capabilities Included |
|---|---|---|---|
| **Open Source** |  (Free Forever) | Developers & DevSecOps | Full static scanner, AIBOM generator, NIST AI RMF & OWASP LLM Top 10 mapping, CVE overlay, SARIF export, \.airomapproved\ format. |
| **Team** |  –  / mo (.4k–.8k/yr) | Startups & Growth companies deploying AI | Phase 1 6-State regulation packs (CA, CO, NY, IL, TX, VA), drift & shadow AI alerts, web compliance dashboard, RegWatch alert feed. |
| **Enterprise** |  – + / yr (ACV) | Regulated Enterprises (Fintech, Health, InsureTech, Gov) | Full 50-state RegWatch, ComplianceDB time-series history, ReportEngine (cloud & on-prem Docker), FilingAgent, Green/Yellow/Red UI, SSO/RBAC, Audit log export, BAA/DPA. |

---

## 6. Competitive Moats

1. **Evidence DNA:** AIROM is the only AIBOM engine that populates CycloneDX \evidence.occurrences[]\ with AST-level \ile:line\ precision. Competitors with UI dashboards cannot produce mathematically verifiable audit trails without rebuilding their static analysis core.
2. **Proprietary Regulatory Data Network:** Every parsed statute, mapped control, and expert-reviewed crosswalk turns legal complexity into a versioned, machine-readable rule pack.
3. **Trust Through Honest Uncertainty:** AIROM marks unproven controls as \manual\ rather than fabricating 100% compliance scores. When auditors test claims, AIROM evidence holds up under legal scrutiny.
