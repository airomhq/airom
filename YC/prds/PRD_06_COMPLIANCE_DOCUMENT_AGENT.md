# PRD-06: Compliance Document Agent & Human Review Gateway

> **Status:** APPROVED FOR IMPLEMENTATION
> **Target Sprint:** Sprint 9 & Sprint 10 (Phase 3/4)
> **Target Package:** services/document/, web/components/filing/
> **Owner:** Fullstack Product & Security Engineer

---

## 1. Problem & Objectives
- **Problem:** Regulatory filings and documentation-on-demand packets are high-liability artifacts. Autonomous AI submissions create massive legal risk for enterprises.
- **Solution:** A **Strict Human-in-the-Loop Gateway** utilizing Green/Yellow/Red validation. The final action is protected by a 90-second ephemeral HMAC confirmation token.
- **Architectural Shift:** Renamed from *FilingAgent* to *ComplianceDocumentAgent* based on statute research showing that Colorado requires produce-on-demand documentation and NYC LL 144 requires public website posting.

---

## 2. Green / Yellow / Red Review UI Specification

`
+==================================================================================+
|  AIROM Compliance Document Gateway — Colorado AI Act Annual Documentation        |
+==================================================================================+
|  [● GREEN: Machine-Verified]                                                     |
|  - System Identity: ResumeRanker v2.4 (OpenAI GPT-4o)               [🔒 LOCKED]   |
|  - High-Risk Trigger: Employment Decisioning (§6-1-1703)           [🔒 LOCKED]   |
|  - Verified Code Evidence: src/ranker.py:12 [View Source ↗]        [🔒 LOCKED]   |
|                                                                                  |
|  [● YELLOW: Human Attestation Required]                                          |
|  - Consumer Notice Delivery Method: [ Dropdown: In-App Banner  v ] * Required    |
|  - Appeal Contact Officer:          [ Text: legal-ops@acme.com   ] * Required    |
|                                                                                  |
|  [● RED: Compliance Gap]                                                         |
|  - Impact Assessment: No completed AIA record in AIBOM (§6-1-1703).             |
|    [ ] Acknowledge known gap (Reason: Under review by outside counsel)           |
|                                                                                  |
|  ------------------------------------------------------------------------------  |
|  Status: 2 of 2 Yellows Answered ✓ | 1 Red Acknowledged ✓                        |
|                                                                                  |
|  [  ✅ CERTIFY & GENERATE PACKAGE (Human)  ] <-- Unlocked Only When Valid        |
+==================================================================================+
`

---

## 3. Human Confirmation Token Security

Endpoint: POST /api/v1/documents/{id}/certify

1. User clicks modal confirmation in browser.
2. Web client requests one-time token: POST /api/v1/auth/human-token.
3. Backend generates HMAC signed with session secret, TTL = 90 seconds.
4. Submit request must include X-Human-Confirmation-Token: <hmac>.
5. CI guardrail verifies zero headless/automated bypass paths exist.

---

## 4. Acceptance Criteria
1. Submission button is physically disabled if any Yellow section is empty.
2. Submitting without a valid, unexpired HMAC token returns HTTP 403 Forbidden.
3. Every certified package generates an immutable entry in iling_audit_log with user ID, timestamp, and AIBOM hash.
