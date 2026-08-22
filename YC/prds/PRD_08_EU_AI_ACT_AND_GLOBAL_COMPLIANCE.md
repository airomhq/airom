# PRD-08: EU AI Act (Regulation (EU) 2024/1689) & Global Compliance Harmonization

> **Status:** READY FOR IMPLEMENTATION
> **Target Sprints:** Sprint 15 & Sprint 16 (Phase 6)
> **Target Directory:** `internal/compliance/specs/`, `services/report/`, `internal/e2e/`
> **Owner:** Lead Regulatory Compliance Engineer

---

## 1. Problem & Executive Objectives

- **Problem:** On August 1, 2024, the European Union's Artificial Intelligence Act (Regulation (EU) 2024/1689) entered into force, establishing the world's most stringent extraterritorial regulatory framework with fines up to €35M or 7% of global annual turnover. Enterprises deploying AI models across US and European markets must comply with disparate requirements (CO SB 24-205, NYC LL144, EU AI Act, ISO/IEC 42001) simultaneously without duplicative manual overhead.
- **Solution:** Embed native, zero-network compliance specifications for the **EU AI Act**, **ISO/IEC 42001:2023**, and **Canadian AIDA** into AIROM, supported by a statutory technical documentation generator that auto-maps code evidence onto statutory articles.
- **Core Objectives:**
  1. **EU AI Act Risk Classification**: Automatically classify AI assets into Prohibited Practices (Title II), High-Risk AI Systems (Title III / Annex III), and General Purpose AI Models (GPAI / Title VIII).
  2. **Statutory Technical Documentation Generator**: Generate complete Annex IV technical documentation packages including training data provenance, model architecture disclosures, compute budgets, and cybersecurity assessments.
  3. **Multi-Standard Cross-Harmonization**: Provide a unified compliance mapping matrix where 1 code scan simultaneously satisfies US State Acts, EU AI Act, and ISO/IEC 42001 standards.

---

## 2. EU AI Act Statutory Mapping Matrix

| Risk Tier / Title | Article Reference | AIROM Control ID | Evaluation Method | Evidence Required |
| :--- | :--- | :--- | :---: | :--- |
| **Prohibited Practices** | Art. 5(1)(a)-(f) | `eu.ai-act.prohibited.biometric-categorization`<br>`eu.ai-act.prohibited.social-scoring`<br>`eu.ai-act.prohibited.subliminal-manipulation` | `gap_if` | Biometric emotion / behavioral manipulation detectors trigger immediate gap. |
| **High-Risk AI Systems** | Art. 9 | `eu.ai-act.high-risk.risk-management` | `manual` | Continuous risk management system documentation. |
| | Art. 10 | `eu.ai-act.high-risk.data-governance` | `evidence_of` | Dataset training provenance, bias mitigation disclosures. |
| | Art. 11 & Annex IV | `eu.ai-act.high-risk.technical-documentation` | `met` / `gap` | Generated Annex IV AIBOM containing complete model/parameter topology. |
| | Art. 12 | `eu.ai-act.high-risk.record-keeping` | `evidence_of` | ComplianceDB hash-chain ledger integration with immutable snapshot history. |
| | Art. 13 | `eu.ai-act.high-risk.transparency-instructions` | `manual` | Clear user instructions and capabilities documentation. |
| | Art. 14 | `eu.ai-act.high-risk.human-oversight` | `manual` | Human-in-the-loop kill-switch and oversight mechanism. |
| | Art. 15 | `eu.ai-act.high-risk.cybersecurity-accuracy` | `gap_if` | Absence of CVEs and unpickling/unsafe model serialization risks. |
| **General Purpose AI (GPAI)** | Art. 53(1)(a) | `eu.ai-act.gpai.technical-documentation` | `evidence_of` | Model architecture, parameter count, training compute FLOPs. |
| | Art. 53(1)(c) | `eu.ai-act.gpai.copyright-policy` | `evidence_of` | Public summary of training data content per EU AI Office template. |
| | Art. 55 | `eu.ai-act.gpai.systemic-risk-mitigation` | `evidence_of` | Adversarial red-teaming and energy consumption disclosures (> 10^25 FLOPs). |

---

## 3. Specification & Data Models

### 3.1 EU AI Act YAML Specification (`internal/compliance/specs/eu-ai-act.yaml`)
```yaml
id: eu-ai-act
name: "EU Artificial Intelligence Act (Regulation (EU) 2024/1689)"
version: "2024/1689"
authority: "European AI Office & National Competent Authorities"
description: "Comprehensive statutory mapping for Prohibited, High-Risk (Annex III), and GPAI systems under EU law."

controls:
  - id: eu.ai-act.prohibited.emotion-recognition
    title: "Prohibition of Workplace/Educational Emotion Recognition (Art. 5(1)(f))"
    category: "Prohibited Practices"
    gap_if: "dataset:biometric&proximity:workplace"
    rationale: "AI systems inferring emotions in workplace or educational settings are strictly prohibited unless for medical/safety reasons."

  - id: eu.ai-act.high-risk.data-governance
    title: "Data and Data Governance (Art. 10)"
    category: "High-Risk AI Systems"
    evidence_of: "dataset&confidence>=0.7"
    rationale: "Training, validation, and testing datasets must be subject to appropriate data governance and bias examination."

  - id: eu.ai-act.high-risk.cybersecurity
    title: "Cybersecurity and Resilience (Art. 15)"
    category: "High-Risk AI Systems"
    gap_if: "risk:unsafe-load|risk:high|cve:critical"
    rationale: "High-risk AI systems must be resilient against unauthorized model access, adversarial attacks, and software vulnerabilities."

  - id: eu.ai-act.gpai.copyright-compliance
    title: "GPAI Copyright Policy and Summary (Art. 53(1)(c))"
    category: "General Purpose AI"
    evidence_of: "hosted-llm|framework:llm"
    rationale: "GPAI model providers must publish a detailed summary of content used for model training."
```

---

## 4. Technical Documentation Generator (`services/report/eu_ai_act.go`)

- **Output Formats:**
  - **EU Technical Documentation (Annex IV)**: Full statutory document containing system description, training methodology, hardware metrics, human oversight protocols, and AST-grounded citations.
  - **EU AI Office Public Transparency Summary**: Public markdown/HTML summary for GPAI model providers.
- **Accessibility:** WCAG 2.1 AA compliant HTML with semantic landmarks, multilingual metadata, and printable vector styling.

---

## 5. Acceptance Criteria

- [ ] `internal/compliance/specs/eu-ai-act.yaml` authored and verified against full regulatory text of Regulation (EU) 2024/1689.
- [ ] `internal/compliance/specs/iso-42001.yaml` and `canada-aida.yaml` authored.
- [ ] Statutory report generator in `services/report/eu_ai_act.go` produces Annex IV compliant documentation packages.
- [ ] Test fixtures created in `internal/e2e/testdata/fixtures/eu-high-risk-app/` and validated deterministically.
- [ ] Zero network requests during scan; 100% offline rule evaluation.
