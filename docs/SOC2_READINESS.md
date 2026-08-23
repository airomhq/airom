# AIROM Enterprise — SOC 2 Type II Compliance & Trust Services Criteria Mapping

> **Classification:** Confidential / Enterprise Governance  
> **Standard:** AICPA Trust Services Criteria (Security, Availability, Confidentiality, Processing Integrity, Privacy)  
> **Target Scope:** AIROM Enterprise Governance Platform & ComplianceDB

---

## 1. Executive Summary

AIROM provides automated AI governance, software composition analysis for machine learning (AIBOM), and runtime security guardrails. This document maps AIROM's technical architecture and operational controls directly to the **AICPA SOC 2 Type II Trust Services Criteria**.

---

## 2. Trust Services Criteria Mapping

### Common Criteria 1: Control Environment (CC1)
- **CC1.1 / CC1.2 (Integrity & Ethical Values)**: All code modifications, release artifacts, and configuration rulepacks are digitally signed with Sigstore/Cosign keyless signatures and tracked via GitHub branch protection with mandatory multi-party code reviews (`CODEOWNERS`).
- **CC1.3 (Management Oversight)**: RBAC boundaries enforce strict role segregation (`Admin`, `ComplianceOfficer`, `Auditor`, `Developer`) across all REST endpoints.

### Common Criteria 6: Logical and Physical Access Controls (CC6)
- **CC6.1 (Zero-Trust Identity & Access)**:
  - Enterprise SSO integration via OpenID Connect (OIDC) / SAML 2.0.
  - JWT session tokens cryptographically signed with HMAC-SHA256 / Ed25519.
  - High-entropy API keys stored hashed using constant-time verification.
- **CC6.6 / CC6.7 (Data Transmission & Perimeter Protection)**:
  - Ingress TLS 1.3 encryption mandatory on all HTTP and SSE gateway streams.
  - Runtime Security Gateway (`services/gateway`) proxies and isolates all LLM inference traffic, preventing unapproved model egress (`HTTP 403`).

### Common Criteria 7: System Operations & Anomaly Detection (CC7)
- **CC7.1 / CC7.2 (Vulnerability Management & Monitoring)**:
  - Real-Time Anomaly Engine (`services/anomaly`) computes cryptographic diffs against cloud deployments, alerting on shadow models or config drift.
  - SIEM Event Streamer (`services/audit`) pipes structured audit events to Datadog, Splunk HEC, and enterprise SIEM collectors.
- **CC7.3 / CC7.4 (Incident Response & ITSM)**:
  - Bi-directional ITSM connector (`services/server/itsm_webhook.go`) dispatches compliance gaps and security defects to Jira and ServiceNow.
  - Automated remediation transitions close tickets when fixes are verified in subsequent CI/CD scans.

### Common Criteria 8: Change Management (CC8)
- **CC8.1 (Immutable Audit Trails & Ledger)**:
  - ComplianceDB (`services/compliancedb`) organizes all scan evidence into an unbroken SHA-256 Merkle hash chain.
  - Bit-drift or unauthorized modifications to historical compliance records are mathematically detected at validation time.

### Processing Integrity (PI1) & Privacy (P1–P8)
- **PI1.1 (AST Grounding & Anti-Hallucination)**:
  - ReportEngine AST Citation Verifier verifies that 100% of claims in generated regulatory reports reference valid code coordinates (`[ev:path:line]`).
  - Uncited claims and fabricated paths are stripped or flagged before document compilation.
- **P1.1 (In-Flight PII & Secret Redaction)**:
  - High-performance streaming redactor (`services/gateway/redact.go`) sanitizes SSNs, credit cards (Luhn mod-10 verified), AWS keys, and OpenAI keys with sub-millisecond overhead.
- **P3.1 (Autonomous Agent Runaway Breaker)**:
  - Sliding-window circuit breaker (`services/gateway/circuit_breaker.go`) halts recursive or runaway agent loops at configured rate ceilings.

---

## 3. Continuous Audit & Attestation Artifacts

| Control ID | AIROM Implementation | Audit Evidence Mechanism |
| :--- | :--- | :--- |
| **SOC2-CC6-AUTH** | Enterprise RBAC & JWT Session Engine | `GET /api/v1/auth/events` |
| **SOC2-CC7-SIEM** | Real-time SSE & SIEM webhook dispatcher | `services/audit/siem.go` |
| **SOC2-CC8-LEDGER** | Unbroken SHA-256 ComplianceDB ledger | `GET /api/v1/repos/{repo}/verify` |
| **SOC2-PI1-GROUND** | AST Citation & Hallucination Verifier | `services/report/qa_adversarial_grounding_test.go` |
| **SOC2-P1-REDACT** | Real-time PII & Luhn Credit Card Filter | `services/gateway/redact.go` |
