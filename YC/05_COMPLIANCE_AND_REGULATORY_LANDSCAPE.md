# AIROM Compliance Platform — Regulatory Landscape & Statutory Matrix

---

## 1. 50-State AI Legislation Matrix (Focus States)

| State & Statute | Core Mandate | Trigger Criteria | Penalties / Risk | AIBOM Evidence Mapping |
|---|---|---|---|---|
| **Colorado AI Act** *(HB24-1468)* | Annual algorithmic impact assessment, consumer disclosure, human oversight appeals. | Deployers & developers of high-risk AI making consequential decisions. | Up to ,000 per violation; AG civil enforcement. | irom:consequential_decision_scope, irom:deployment.disclosure_mechanism, irom:decision.appeal_mechanism |
| **California AI Act** *(SB 1047 / AB 2013 / AB 3030)* | AI transparency disclosures, frontier model safety testing, training data source reporting. | GenAI models deployed to CA consumers or training compute > 10^26 FLOPs. | Civil injunctions + ,000-,000 per violation. | model_name, provider, 	raining_data_provenance, safety_filtering_config |
| **NYC Local Law 144** | Mandatory independent annual bias audit and public posting before tool use. | Automated Employment Decision Tools (AEDTs) used on NYC applicants. | –,500 per day per affected candidate. | File path proximity (hiring, 
esume), ias_audit_date, impact_ratio |
| **Illinois BIPA** *(740 ILCS 14)* | Explicit written consent & retention schedules for biometric AI. | Any AI processing facial geometry, voiceprints, or biometric markers. | ,000 (negligent) to ,000 (reckless) per scan violation. | Model kind iometric-vision, oice-embedding, dataset metadata |
| **Texas CAPAIA** | Disclosure of synthetic media and automated commercial decision profiling. | Commercial AI services operating in Texas. | Deceptive Trade Practices Act penalties (up to ,000 per violation). | hosted-llm, system_prompt_disclosure, synthetic_output_tag |
| **Virginia CDPA** | Data protection assessment for AI engaging in profiling with legal effect. | Data controllers processing VA consumer data with AI profiling. | Up to ,500 per willful violation. | High-risk classification tag, PII dataset links |

---

## 2. Federal Framework Crosswalk

AIROM maps every code-level component into the major federal and global AI frameworks:
1. **NIST AI RMF 1.0:** GOVERN, MAP, MEASURE, MANAGE functions.
2. **OWASP Top 10 for LLM Applications & Agentic AI:** Prompt Injection (LLM01), Insecure Output Handling (LLM02), Training Data Poisoning (LLM03), Model Denial of Service (LLM04), Supply Chain Vulnerabilities (LLM05).
3. **FTC Act Section 5:** Enforcement against deceptive claims regarding AI safety, bias, or performance.
4. **EU AI Act:** Prohibited, High-Risk, and General Purpose AI (GPAI) transparency categories.
