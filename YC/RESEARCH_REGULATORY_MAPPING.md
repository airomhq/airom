# AIROM Compliance Platform — Regulatory Statute Mapping & Filing Requirements

> [!WARNING]
> **CRITICAL LEGISLATIVE UPDATE:** California SB 1047 (AI Safety) was VETOED on September 29, 2024. It is NOT active law and all compliance checks or references related to it have been removed from the platform.

> [!NOTE]
> Most states do NOT have submission portals for AI compliance. Compliance generally involves documentation-on-demand (produced during regulatory inquiry) or public website posting.

## 1. Colorado AI Act (SB 24-205)
- **Effective Date:** February 1, 2026
- **Enforcement:** Colorado AG as unfair/deceptive trade practice, up to $20,000 per violation, no private right of action
- **Key Obligations:**
  1. **Risk Management Program (§6-1-1702):** Must implement a risk management program aligned with nationally recognized frameworks (e.g., NIST AI RMF). 
     - *Verdict:* MANUAL (quality of program requires human assessment)
  2. **Impact Assessments (§6-1-1703):** Annual impact assessment for high-risk AI making consequential decisions. 
     - *Verdict:* MET/GAP (verifiable via `assessment_date` in AIBOM)
  3. **Consumer Notice (§6-1-1704):** Notify consumers of AI interaction, right to opt-out, right to appeal. 
     - *Verdict:* MANUAL (UI/UX verification needed)
  4. **Incident Reporting (§6-1-1705):** Report algorithmic discrimination to AG within 90 days. 
     - *Verdict:* MANUAL
- **Filing:** NO proactive portal. Documents must be produced upon AG request only.
- **AIBOM Fields:** `risk_classification`, `assessment_date`, `framework_name`, `deployment_UI_flags`

## 2. NYC Local Law 144 (2021)
- **AEDT Definition:** Computational process (ML/AI/stats) that substantially assists or replaces discretionary decision-making for employment.
- **Bias Audit:** Independent audit within 1 year prior to use.
- **Public Posting:** Summary on employer's website (careers page), posted for 6 months after last use.
- **Required Data in Summary:** Audit date, tool distribution date, source data description, selection rates, and impact ratios across race/ethnicity/sex.
- **Notice:** 10 business days advance notice to NYC candidates/employees.
- **Enforcement:** NYC DCWP, $500 first violation, up to $1,500 per subsequent violation per day.
- **Verdict Types:** `last_audit_date` and `impact_ratio` -> MET/GAP, `auditor_credentials` -> MANUAL
- **Filing:** NO portal. Public website posting + advance notice to candidates.

## 3. California AI Legislation
- **SB 1047 (AI Safety):** **VETOED September 29, 2024 — NOT IN FORCE**
- **AB 2013 (AI Transparency):**
  - **Effective:** Jan 1, 2026
  - **Obligation:** Developers of generative AI must post a training data summary (sources, ownership, volume, IP status, PII presence, synthetic data).
  - *Verdict:* MET/GAP for `training_data_summary` field.
  - **Filing:** Post on developer's website.
- **AB 3030 (Healthcare AI):**
  - **Effective:** Jan 1, 2025
  - **Obligation:** Healthcare providers using GenAI for patient communication must include a prominent disclaimer unless reviewed by a licensed provider.
  - *Verdict:* MANUAL
- **CCPA/CPRA:** Right to opt-out of automated decision-making/profiling. 
  - *Verdict:* MANUAL

## 4. Illinois BIPA (740 ILCS 14)
- **Trigger:** Collection/storage/use of biometric identifiers (retina, iris, fingerprint, voiceprint, facial geometry).
- **AI/ML Model Types Triggering BIPA:** Facial recognition, voice analytics/voiceprints, fingerprint access.
- **Obligations:** Written informed consent, public retention/destruction policy (within 3 years), prohibition on profiting from biometric data.
- **AIBOM Trigger:** Models with `data_type: biometric`, `model_type: facial_recognition`, `data_modality: voice_audio`.
- **Verdict:** MANUAL for consent verification. MET/GAP for existence of retention policy document.
- **Penalty:** $1,000 negligent, $5,000 reckless per violation.

## 5. Texas TRAIGA (H.B. 149)
- **Effective Date:** Jan 1, 2026
- **Approach:** Harm-based approach, NOT comprehensive risk assessments.
- **Prohibits:** Manipulation, social scoring by government, unlawful discrimination, biometric capture without consent.
- **AIBOM mapping:** `intended_use`, `banned_use_flag` -> MET/GAP

## 6. Virginia VCDPA
- **Obligations:** Profiling opt-out right for decisions producing legal/significant effects. Data Protection Assessment required for high-risk processing.
- **Enforcement:** VA AG only.
- **AIBOM:** `model_purpose: profiling`, `dpa_completion_date` -> MET/GAP

## 7. Cross-State Conflict Analysis
- **Transparency vs. Trade Secrets:** CA AB 2013 training data transparency vs. trade secret protections in other states.
- **Data Retention vs. Destruction:** IL BIPA data destruction requirements vs. NYC LL144 audit data retention periods.
- **Definitions:** Divergent definitions of 'high-risk' across CO, VA, and federal frameworks.

## 8. Master Regulatory Mapping Table

| Statute Section | Obligation Type | Testable from AIBOM? | AIBOM Field Needed | Verdict Type | Filing Method |
| :--- | :--- | :--- | :--- | :--- | :--- |
| CO SB 24-205 §6-1-1702 | Risk Management Program | Partial | `framework_name` | MANUAL | Document-on-Demand |
| CO SB 24-205 §6-1-1703 | Impact Assessment | Yes | `assessment_date` | MET/GAP | Document-on-Demand |
| CO SB 24-205 §6-1-1704 | Consumer Notice | No | `deployment_UI_flags` | MANUAL | User Interface |
| CO SB 24-205 §6-1-1705 | Incident Reporting | No | N/A | MANUAL | AG Notification |
| NYC LL144 | Bias Audit | Yes | `last_audit_date`, `impact_ratio` | MET/GAP | Public Website Posting |
| CA AB 2013 | Training Data Transparency | Yes | `training_data_summary` | MET/GAP | Public Website Posting |
| CA AB 3030 | Healthcare Disclaimer | No | N/A | MANUAL | User Interface |
| CA CCPA/CPRA | ADM Opt-Out | No | N/A | MANUAL | User Interface |
| IL BIPA (740 ILCS 14) | Retention Policy | Yes | `retention_policy_doc` | MET/GAP | Public Policy |
| IL BIPA (740 ILCS 14) | Informed Consent | No | N/A | MANUAL | User Interface |
| TX TRAIGA (H.B. 149) | Prohibited Uses | Yes | `intended_use`, `banned_use_flag` | MET/GAP | N/A |
| VA VCDPA | Data Protection Assessment | Yes | `dpa_completion_date` | MET/GAP | Document-on-Demand |

## 9. Impact on AIROM Product Design
- **Filing Paradigm Shift:** FilingAgent is NOT about "submitting to a state portal". It is fundamentally about **documentation preparation** and **public posting generation**.
- **Delivery Mechanism:** Most compliance is produce-on-demand (e.g., CO) or publish-on-website (e.g., NYC LL144, CA AB 2013).
- **Core Value Proposition:** The product value resides in continuous monitoring and instant evidence assembly, not in portal submissions.
- **Action Item:** Rename `FilingAgent` to `ComplianceDocumentAgent` (or similar) to better reflect its actual responsibilities.
