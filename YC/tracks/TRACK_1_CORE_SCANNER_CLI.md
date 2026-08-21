# Track 1: Core Scanner & Developer CLI

> **Ownership:** Lead Go Systems Engineer  
> **Key Focus:** AST & Byte-level Detectors, Invariant Enforcement, Local CVE Overlay, .airomapproved CLI Primitives, CI Integration.

---

## 1. Scope & Technical Objectives

1. **Performance & Invariants:** Maintain 8 locked invariants (Read-once, Bounded Memory, Pure Go CGO=0, Deterministic Output).
2. **Detection Breadth Expansion:** Expand parsing from 7 kinds to support new embedding models, agentic frameworks (CrewAI, LangGraph, AutoGen), and local LLM runtime configs (vLLM, Ollama, TensorRT).
3. **Governance Primitives (.airomapproved):** Implement native CLI subcommands to inspect, approve, and verify component allowlists with cryptographic tamper-detection.
4. **Zero-Network Guarantee:** Maintain strict architectural separation: irom scan never initiates network sockets.

---

## 2. Sprint Backlog & Epics (Months 0–6)

### Epic T1.1: .airomapproved Engine (Sprint 1–3)
- [ ] Implement irom approve <component_purl> --scope <path_glob> writing to .airomapproved.
- [ ] Implement irom revoke <component_purl> with tombstone audit records.
- [ ] Implement irom diff --approved producing instant local terminal warnings for unapproved items.
- [ ] Add SHA-256 manifest signature block to .airomapproved to detect manual tampering.

### Epic T1.2: AI Dependency CVE Expansion (Sprint 2–4)
- [ ] Expand OSV.dev query batching to cover 30+ new AI Python & JS packages.
- [ ] Implement local caching for CVE advisories with offline fallback.
- [ ] Add --fix manifest pin updates for direct dependencies.

### Epic T1.3: SARIF & GitHub Code Scanning CI Action (Sprint 3–5)
- [ ] Refine SARIF 2.1.0 output schema mapping NIST AI RMF and OWASP LLM Top 10 rule IDs.
- [ ] Publish iromhq/airom-action@v1 on GitHub Marketplace with zero-config setup.
- [ ] Add PR inline comment annotations for high-severity CVEs and Shadow AI.

---

## 3. Definition of Done (DoD)
- All unit and golden fixture tests pass (go test ./...).
- Zero memory regressions (RSS <= 35MB on 100k LOC scan).
- go list -deps ./cmd/scan/... | grep net/http returns exit code 0 (no network imports).
