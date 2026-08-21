# PRD-04: AnomalyEngine Cloud Diff & Policy-As-Code

> **Status:** APPROVED FOR IMPLEMENTATION
> **Target Sprint:** Sprint 4 (Phase 2)
> **Target Service:** services/anomaly/
> **Owner:** Cloud Backend & Policy Engineer

---

## 1. Problem & Objectives
- **Problem:** CI builds should not fail on raw data; they must fail when code changes violate organizational governance policies (Shadow AI, Model Swaps, Config Drift).
- **Solution:** A cloud-hosted, pure rule-based diff engine (zero statistical ML baselines in Phase 1). Computes semantic deltas between base and head scans in < 50ms.

---

## 2. API Contract & Data Payloads

Endpoint: POST /api/v1/anomaly/evaluate

### Request Payload:
`json
{
  "repo_id": "d3b07384-d113-46d8-8b9f-02d26f028882",
  "base_commit": "a1b2c3d",
  "head_commit": "e4f5g6h",
  "head_aibom": { "cyclonedx_json": "..." },
  "manifest": { "approved_manifest_yaml": "..." }
}
`

### Response Payload:
`json
{
  "clean": false,
  "highest_severity": "HIGH",
  "anomalies": [
    {
      "id": "ANOM-01",
      "type": "shadow-ai",
      "severity": "HIGH",
      "component": "pkg:pypi/openai@1.51.0",
      "location": "src/app.py:8",
      "message": "Shadow AI: Component not declared in .airomapproved manifest.",
      "remediation": "Run irom approve pkg:pypi/openai@1.51.0 --scope src/app.py"
    },
    {
      "id": "ANOM-02",
      "type": "regulatory-proximity-hiring",
      "severity": "HIGH",
      "location": "src/hiring/ranker.py:14",
      "message": "Employment-domain AI detected. Triggers NYC Local Law 144 bias audit requirement.",
      "statute_ref": "NYC LL144 §20-871"
    }
  ]
}
`

---

## 3. Acceptance Criteria
1. Diff evaluation completes in < 50ms for repos with 1,000+ components.
2. Unchanged .airomapproved components yield zero false-positive alerts.
3. Path heuristics (hiring/, credit/, patient/) trigger respective sector proximity alerts.
