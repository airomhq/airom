# AIROM Compliance Platform — 12-Month Execution Roadmap

---

## 1. Milestone Overview

`
Months 0-3: OOTB Foundation (Free Tier Hook + First 2 Paid State Packs)
Months 3-6: Enterprise Intelligence (RegWatch + ComplianceDB + Integrations)
Months 6-9: ReportEngine & On-Prem (LLM Report Generator + On-Prem Docker)
Months 9-12: FilingAgent & Enterprise Scale (Auto-Filing UI + 50-State Scale)
`

---

## 2. Detailed Milestone Breakdown

### 🎯 Months 0–3: OOTB Foundation — Ship Fast
- [ ] **CVE Overlay Expansion:** Add 20+ AI libraries (vLLM, Ollama, ONNX Runtime, LlamaIndex, LiteLLM) to automated OSV.dev vulnerability lookup.
- [ ] **GitHub Code Scanning Action:** Publish official GitHub Action producing native SARIF alerts in PR security tabs.
- [ ] **.airomapproved CLI Tooling:** Implement irom approve <id> and irom revoke <id> with git-backed manifest signature validation.
- [ ] **Compliance Dashboard MVP:** Web UI showing per-regulation status (Met / Gap / Manual) pushed via API keys.
- [ ] **Colorado AI Act & NY LL 144 Packs:** Release Phase 1 paid regulation packs with full control crosswalks.
- **Exit Criteria:** A developer can install AIROM, run a scan, and view their CVE + NIST/State compliance posture in < 5 minutes.

---

### 🎯 Months 3–6: Enterprise Intelligence
- [ ] **RegWatch Ingestion Engine:** Automated scrapers for CA, CO, NY, IL, TX, VA state legislative portals + FTC / EEOC guidance.
- [ ] **ComplianceDB v1:** Multi-repo organizational state machine with time-series history and incident tracking.
- [ ] **IT Adapters (Agentless & Agent):** Webhook adapters for Jira (auto-ticket on gap), Slack (alerts), and GitHub Checks.
- [ ] **Community Benchmarking:** Aggregated, k-anonymized benchmark engine for free tier users.
- [ ] **CA, IL, TX, VA Regulation Packs:** Complete Phase 1 state coverage.
- **Exit Criteria:** Enterprise teams can track compliance across 50+ repositories over 6 months of historical data.

---

### 🎯 Months 7–9: ReportEngine & On-Premise Support
- [ ] **ReportEngine Cloud Service:** Evidence-anchored LLM report generation for Colorado AI Act, NY LL 144, and NIST AI RMF.
- [ ] **Citation Verifier:** Post-processing AST citation validator that strips ungrounded statements.
- [ ] **On-Premises Docker Container:** irom/report-engine:latest for air-gapped / BYOK (Azure OpenAI / Ollama) deployments.
- [ ] **Phase 2 State Expansion:** Release regulation packs for WA, FL, MA, GA, PA, OH, MI.
- **Exit Criteria:** A compliance officer can generate a legally certified Colorado AI Act annual attestation in < 10 minutes.

---

### 🎯 Months 10–12: FilingAgent & Enterprise Scale
- [ ] **FilingAgent UI:** Green/Yellow/Red filing review dashboard with locked submission safeguards.
- [ ] **State Portal Adapters:** Direct REST API connector for Colorado AG Portal + PDF form-fill fallback.
- [ ] **Renewal Tracker:** Calendar synchronization (Google/Outlook) with 90/30/7-day escalating alert tiers.
- [ ] **Phase 3 Automation:** Scale to all 50 states using automated LLM statute parsing with human spot-checks.
- [ ] **Enterprise GTM:** SOC 2 Type II certification, SAML/OIDC SSO, Role-Based Access Control, and HIPAA BAA support.
- **Exit Criteria:** Customers submit real annual compliance filings directly from AIROM with full audit-trail defense.
