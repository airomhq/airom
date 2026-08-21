# Track 5: ReportEngine & Evidence Grounding

> **Ownership:** Fullstack / LLM Application Engineer  
> **Key Focus:** Evidence-Anchored Prose Generation, AST Citation Validation, Typst PDF / HTML / DOCX Rendering, On-Prem BYOK Container.

---

## 1. Scope & Technical Objectives

1. **Zero Hallucination Guarantee:** Every sentence must carry an inline [ev:...] citation matching an AIBOM occurrence.
2. **Met / Gap / Manual Tri-State Prose:** Pre-filled prose for met, clear remediation instructions for gap, blank attestation blocks for manual.
3. **Multi-Format Export:** High-quality PDF (via Typst), standalone HTML (for NY LL144 web posting), Word DOCX (with track-changes for legal), and Markdown.
4. **On-Premise Privacy Option:** Docker image (irom/report-engine) supporting Azure OpenAI, Bedrock, and self-hosted Ollama.

---

## 2. Sprint Backlog & Epics (Months 6–10)

### Epic T5.1: LLM Prompt Engine & Citation Verifier (Sprint 12–15)
- [ ] Design structured JSON-to-Prose prompt templates for Colorado AI Act and NIST AI RMF.
- [ ] Implement AST-level Citation Verifier that rejects and strips uncited assertions.
- [ ] Build [MANUAL ATTESTATION REQUIRED] formatter for subjective policy requirements.

### Epic T5.2: Multi-Format Document Renderers (Sprint 14–17)
- [ ] Typst backend renderer producing publication-grade audit PDFs with embedded evidence tables.
- [ ] WCAG 2.1 AA accessible HTML generator for NY LL 144 public web posting mandate.
- [ ] python-docx export with editable sections for corporate legal counsel review.

### Epic T5.3: On-Premise BYOK Docker Container (Sprint 16–19)
- [ ] Package standalone container irom/report-engine:latest.
- [ ] Support provider backends: OpenAI, Anthropic Claude, Azure OpenAI, AWS Bedrock, local Ollama.
- [ ] CLI configuration integration (~/.airom/config.yaml endpoint override).

---

## 3. Definition of Done (DoD)
- 100% of factual claims in generated PDF reports link to verifiable file:line evidence.
- Full Colorado AI Act report generation completes in < 15 seconds.
- On-prem container runs completely air-gapped with zero outbound telemetry.
