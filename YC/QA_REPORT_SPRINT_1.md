# AIROM Sprint 1 QA Test Report

## 1. Test Summary & Matrix

| Test Phase | Scenarios Executed | Pass | Fail | Status |
|---|---|---|---|---|
| Phase 1: Functional CLI Test Suite | 4 | 4 | 0 | **PASS** |
| Phase 2: State Regulation Compliance Specs | 4 | 4 | 0 | **PASS** |
| Phase 3: Output Format Validation | 3 | 3 | 0 | **PASS** |
| Phase 4: Performance & Memory Benchmark | 2 | 2 | 0 | **PASS** |

**Overall Status**: **PASS**

## 2. Functional Test Results

- **Approval Lifecycle**: Validated correctly. Unapproved components (`openai`, `anthropic`, `gpt-3.5-turbo`, `claude-3-haiku`) successfully cause a `check` failure (exit code 1). Issuing `airom approve` enables successful validation (exit code 0). `airom revoke` appropriately reinstates failures.
- **Scope Boundaries**: Successfully verified. Moving an approved model call (e.g. `gpt-3.5-turbo` approved for `src/**`) outside of its approved scope (e.g., to `scripts/helper.py`) correctly triggers a `scope_mismatch` failure.
- **Deny List Override**: Verified. Manually injecting a `deny:` section in `.airomapproved` for a component already in the `approved:` list successfully revokes its approved status and fails the check. *(Note: See Defect Log for UI/UX quirk)*.

## 3. State Regulation Compliance Specs

Tested the `--compliance` flags for major AI governance acts:
- **Colorado AI Act (`colorado-ai-act`)**: Passed. Output reports 4 controls (3 manual, 1 met).
- **NYC LL144 (`nyc-ll144`)**: Passed. Output reports 2 controls covering bias audits (2 manual).
- **CA AB 2013 (`ca-ab2013`)**: Passed. Output reports 1 control for Generative AI Training Data Transparency.
- **Combined Flags**: Passed. Able to pipe multiple `--compliance` flags into a single consolidated report.

## 4. Output Format Validation

Successfully verified alternate output structures:
- **JSON (`scan.json`)**: Emits valid JSON, properly embedding custom `props` array (e.g., `"name": "airom:governance.status", "value": "approved"`).
- **CycloneDX (`bom.cdx.json`)**: Valid spec with proper `"bomFormat": "CycloneDX"` headers.
- **SARIF (`scan.sarif`)**: Conforms to standard `2.1.0` syntax.

## 5. Performance Benchmarks

*Hardware: Standard QA environment (Windows)*
- **Execution Time**: `~689 ms` per scan on average for small/medium repository.
- **Peak RSS Memory**: `~36.7 MB` (Very lightweight, ideal for CI/CD runners).

## 6. Security & Adversarial Findings

- **Signature Evasion / Manual Tampering**: Modifying the `.airomapproved` file manually to include `deny:` overrides did *not* result in a hard signature parsing crash. While it technically succeeded in processing the deny instruction, relying on manual edits could invalidate future automated UI workflows. 

## 7. Defect Log

| ID | Severity | Description | Recommendation |
|---|---|---|---|
| DEF-01 | Minor/UI | Explicit deny overrides approval but the CLI reports the generic `Status: unapproved, Reason: Component not found in approved list` instead of specifying that it was explicitly denied. | Add a specific error status (e.g., `Status: explicitly_denied`) for clarity. |

## 8. QA Sign-Off Status

**Decision**: **GO FOR PRODUCTION**

The Sprint 1 release candidates meet all functional, security, and performance benchmarks. Defect DEF-01 is a minor UX issue that does not affect the core security boundaries or logic of the application.
