# PRD-02: Regulation Packs & Colorado AI Act (SB 24-205)

> **Status:** APPROVED FOR IMPLEMENTATION
> **Target Sprint:** Sprint 3 (Phase 1)
> **Target Package:** internal/compliance/specs/, internal/compliance/
> **Owner:** Legal Systems & Compliance Engineer

---

## 1. Problem & Objectives
- **Problem:** AI teams must comply with state regulations (Colorado AI Act SB 24-205, NYC LL 144, California AB 2013). Manual audits take weeks and miss code-level triggers.
- **Solution:** Declarative YAML compliance specifications embedded directly in AIROM (internal/compliance/specs/). The existing engine evaluates controls against AIBOM components in milliseconds.
- **CRITICAL DISCOVERY:** Adding new compliance packs requires **ZERO Go code changes**. The //go:embed specs/*.yaml directive loads all YAML specs automatically.

---

## 2. Colorado AI Act (HB24-1468 / SB 24-205) Specification

Statute: Colorado Artificial Intelligence Act
Effective Date: **February 1, 2026**
Enforcement: Colorado Attorney General (,000 max penalty per violation)
File: internal/compliance/specs/colorado-ai-act.yaml

`yaml
id: colorado-ai-act
title: "Colorado Artificial Intelligence Act (SB 24-205)"
version: "1.0"
jurisdiction: "US-CO"
effective_date: "2026-02-01"
statute_url: "https://leg.colorado.gov/bills/sb24-205"

controls:
  - id: co.ai-act.risk-mgmt
    section: "§6-1-1702"
    title: "Risk Management Program Alignment"
    description: "Deployer must implement a risk management policy aligned with nationally recognized frameworks (e.g. NIST AI RMF)."
    manual: true
    attestation_prompt: "Confirm that organizational AI risk management policy is documented and reviewed annually."

  - id: co.ai-act.impact-assessment
    section: "§6-1-1703"
    title: "Algorithmic Impact Assessment"
    description: "Annual impact assessment required for high-risk AI making or substantially influencing consequential decisions."
    evidence_of:
      kind: [hosted-llm, framework, model]
      property:
        name: "airom:assessment.date"
        operator: exists
    gap_if:
      kind: [hosted-llm, framework]
      property:
        name: "airom:risk.consequential_decision"
        value: "true"
    gap_message: "§6-1-1703: High-risk consequential AI system deployed without completed Algorithmic Impact Assessment."
    remediation: "Conduct an Algorithmic Impact Assessment per CDPHE guidelines and record completion date in manifest."

  - id: co.ai-act.consumer-notice
    section: "§6-1-1704"
    title: "Consumer AI Interaction & Consequential Decision Notice"
    description: "Deployer must disclose to consumers that they are interacting with AI, state system purpose, and provide opt-out/appeal pathways."
    manual: true
    attestation_prompt: "Confirm consumer-facing UI includes AI disclosure statement and appeal contact mechanism."

  - id: co.ai-act.incident-reporting
    section: "§6-1-1705"
    title: "Algorithmic Discrimination Reporting"
    description: "Report known incidents of algorithmic discrimination to Colorado AG within 90 days of discovery."
    manual: true
    attestation_prompt: "Confirm incident response protocol includes 90-day Colorado AG reporting trigger."
`

---

## 3. NYC Local Law 144 (2021) Specification

File: internal/compliance/specs/nyc-ll144.yaml

`yaml
id: nyc-ll144
title: "NYC Local Law 144 — Automated Employment Decision Tools (AEDT)"
version: "1.0"
jurisdiction: "US-NY-NYC"
statute_url: "https://www.nyc.gov/site/dca/about/automated-employment-decision-tools.page"

controls:
  - id: nyc.ll144.bias-audit
    section: "§20-871(a)"
    title: "Annual Independent Bias Audit"
    description: "AEDT must undergo an independent bias audit within one year prior to use."
    evidence_of:
      property:
        name: "airom:bias_audit.date"
        operator: exists
    gap_if:
      path_contains: ["hiring", "resume", "applicant", "candidate", "recruitment"]
    gap_message: "§20-871(a): Employment-domain AI component detected without verified independent bias audit."
    remediation: "Commission an independent bias audit calculating adverse impact ratios across race/ethnicity/sex."

  - id: nyc.ll144.public-posting
    section: "§20-871(b)"
    title: "Public Website Posting of Bias Audit Summary"
    description: "Post summary of bias audit and distribution date publicly on careers website."
    manual: true
    attestation_prompt: "Confirm bias audit summary is publicly posted at careers URL and maintained for 6 months after tool use."
`

---

## 4. California AB 2013 (Generative AI Transparency) Specification

File: internal/compliance/specs/ca-ab2013.yaml
*Note: Replaces vetoed SB 1047.*

`yaml
id: ca-ab2013
title: "California AB 2013 — Generative AI Training Data Transparency"
version: "1.0"
jurisdiction: "US-CA"
effective_date: "2026-01-01"
statute_url: "https://leginfo.legislature.ca.gov/faces/billNavClient.xhtml?bill_id=202320240AB2013"

controls:
  - id: ca.ab2013.training-data-summary
    section: "Chapter 33 §22757.2"
    title: "Training Data Source Disclosure"
    description: "Post high-level summary of datasets used to train generative AI (sources, volume, PII presence, IP status)."
    evidence_of:
      property:
        name: "airom:training_data.summary_url"
        operator: exists
    gap_if:
      kind: [model, hosted-llm]
    gap_message: "AB 2013: Generative AI model deployed without public training data provenance disclosure."
`

---

## 5. Acceptance Criteria & Test Cases
1. irom scan testdata/fixtures/co_compliant_app/ --compliance colorado-ai-act outputs all controls as MET or MANUAL.
2. irom scan testdata/fixtures/co_noncompliant_app/ --compliance colorado-ai-act flags co.ai-act.impact-assessment as GAP with exit code 1.
3. NYC LL144 fixture correctly identifies employment-path heuristics.
