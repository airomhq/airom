# AIROM Compliance Platform — gstack Assessment & YC Office Hours

> **Methodology:** Applied Garry Tan's [gstack](https://github.com/garrytan/gstack) product interrogation framework (/office-hours + /plan-ceo-review + /plan-devex-review).

---

## 1. YC Office Hours: 6 Forcing Questions

### Question 1: What is the core pain, in specific instances rather than hypotheticals?
- **The Raw Pain:** An engineering team at a Series B fintech deploys a credit scoring agent. In August 2026, their General Counsel receives a letter from the Colorado Attorney General demanding documentation of consumer disclosure mechanisms (§6-1-1705) and an algorithmic impact assessment (§6-1-1706) for all AI systems in production.
- **The Failure Mode Today:** Engineering sends a list of packages from 
equirements.txt. Legal has no idea what chromadb or langchain does. The compliance manager spends 3 weeks manually auditing git repos, drafting a 40-page Word document, and guessing when models were deployed. Meanwhile, an engineer swapped gpt-4 for gpt-4o two weeks ago without telling legal, invalidating their draft filing.
- **The Realized Insight:** Compliance failure is not a legal problem; it is a **code visibility and drift problem**.

---

### Question 2: Who is the desperate user?
- **Primary:** The **Head of Compliance / General Counsel** at companies with 20–500 engineers deploying AI. They are legally liable for violations (up to ,000/violation in CO, ,500/day in NY) and have zero real-time visibility into what engineers are committing to production.
- **Secondary:** The **Security Lead / VP of Eng** who gets interrupted by compliance questionnaires and manual audit requests every quarter.

---

### Question 3: What is the narrowest wedge that solves real pain tomorrow?
- **The Narrow Wedge:** **irom scan . --compliance colorado-ai-act + .airomapproved**.
- An engineer runs one CLI command in CI. It maps their code directly to Colorado statutory controls and outputs a deterministic met / gap / manual verdict with ile:line proof.
- If an unapproved model is added in a PR, CI fails with SHADOW_AI_DETECTED.
- **Time-to-Value:** 90 seconds. No cloud sign-up required, no enterprise procurement needed to start.

---

### Question 4: What is the 10-Star Product hiding inside this request?
- **1-Star:** A CSV spreadsheet template of AI regulations.
- **3-Star:** A static scanner that outputs a list of AI libraries.
- **5-Star:** A scanner that checks code against NIST AI RMF and outputs a PDF report.
- **10-Star Product:** **Autonomous Compliance Infrastructure**.
  - Software that continuously watches 50 state legislatures, translates statutes into code-level predicates, detects drift in CI/CD before code merges, maintains a tamper-evident time-series ledger, writes regulator-ready audit reports where every sentence links to source code, and prepares certified state filings where the compliance officer only has to review 2 human-attestation fields and click Submit.

---

### Question 5: What are the 4 Scope Modes (/plan-ceo-review)?
1. **Expansion (The Trap):** Trying to build full GRC (competing with Vanta/Drata across SOC 2, ISO 27001, HIPAA) and covering all 50 states on Day 1. *Verdict: REJECT.*
2. **Reduction (Too Narrow):** Just an open-source AIBOM generator that outputs CycloneDX JSON. Developers like it, but nobody pays /yr for a JSON file. *Verdict: REJECT.*
3. **Selective Expansion (The Winning Strategy):**
   - Keep the **Scanner Core open-source** (CGO=0, zero network, fast distribution).
   - Focus commercially on **AI-specific regulatory compliance** where Vanta and Drata have zero AST-level code visibility.
   - Launch Phase 1 with the **6 highest-enforcement states** (CA, CO, NY, IL, TX, VA).
   - Monetize via Cloud Intelligence (RegWatch, ComplianceDB time-series, ReportEngine, FilingAgent).

---

### Question 6: What is the magical developer moment (/plan-devex-review)?
- **The Moment:** Running irom scan . on an existing messy repo and seeing a terminal table 2 seconds later that says:
  `
  AI Bill of Materials — 7 components found
  Vulnerabilities: 2 (1 high, 1 medium)
  Colorado AI Act Status: 2 MET, 1 GAP (Missing Consumer Disclosure in src/app.py:8)
  `
- Instant realization: *"This tool already knows my code better than my compliance team does."*

---

## 2. Strategic Scope Lock

`
+-------------------------------------------------------------------------------+
| CORE ENGINE (Open Source)     | CLOUD PLATFORM (Paid Enterprise)              |
+-------------------------------+-----------------------------------------------+
| - AST & Byte Detectors        | - RegWatch 50-State Daily Crawlers            |
| - NIST / OWASP / State Packs  | - ComplianceDB Multi-Repo Hash-Chained Ledger |
| - CVE Overlay (OSV.dev)       | - AnomalyEngine Cloud Webhooks & Alerts       |
| - .airomapproved CLI          | - ReportEngine Evidence-Anchored LLM Writer   |
| - SARIF CI Export             | - FilingAgent Green/Yellow/Red Gateway        |
+-------------------------------------------------------------------------------+
`
