# AIROM Compliance Platform - gstack Sprint Methodology and Quality Gates

Source: Applied analysis of Garry Tan's gstack framework, adapted for a Go CLI + Cloud Services project.

---

## 1. Sprint Sequence (gstack-Aligned)

Every 2-week sprint follows the gstack sequence: Think, Plan, Build, Review, Test, Ship, Reflect

| Day | Activity | gstack Skill | AIROM Adaptation |
|---|---|---|---|
| Day 1 | Ideation and Pain Framing | /office-hours | 6 Forcing Questions: Demand Reality, Status Quo, Desperate Specificity, Narrowest Wedge, Observation, Future-fit. Output: design doc for the sprint features. |
| Day 2 | Spec Authoring | /spec | 5-phase spec: Why, Scope, Technical (mandatory code-reading of AIROM internals), Draft, File. Codex quality gate: blocks specs scoring below 7/10 for executability. |
| Day 2-3 | Strategic Review | /plan-ceo-review | Lock scope using one of 4 modes: Expansion, Selective Expansion, Hold Scope, Reduction. Lock architectural decisions. |
| Day 3-4 | Engineering Architecture | /plan-eng-review | ASCII diagrams for data flow, state machines, error paths. Test matrix. Failure modes. Shadow path validation (nil input, empty input, upstream error). |
| Day 4 | Security Threat Model | /cso | OWASP Top 10 + STRIDE adapted for CLI: command injection, file permissions, secret management, path traversal. 8/10+ confidence gate. |
| Day 5-8 | Implementation | (build) | Feature development against spec. Use /investigate for root-cause debugging. |
| Day 9 | Code Review | /review | Staff engineer review: auto-fix obvious issues, flag completeness gaps, verify invariants maintained. |
| Day 10 | Release Engineering | /ship | Sync main, run go test, audit coverage, push, open PR. Bootstrap test frameworks if missing. |

---

## 2. Quality Gates (Every Feature Must Pass)

### Gate 1: Spec Executability (Score >= 7/10)
- The /spec phase produces a spec document.
- An unfamiliar engineer must be able to implement the feature from the spec alone.
- If the Codex evaluator scores the spec below 7/10, it is rejected and rewritten.

### Gate 2: Redaction and Privacy
- Semantic and regex scanners verify no NDA-bound material, internal codenames, or PII leaked in specs or docs.
- Regulation pack YAML must not contain customer-specific data.

### Gate 3: Architecture Diagramming
- /plan-eng-review must produce ASCII diagrams for ALL new data flows.
- State machines must be explicitly defined for any stateful feature (ComplianceDB, AnomalyEngine).

### Gate 4: Shadow Path Validation
- Engineering plan must name and handle edge cases:
  - What happens when .airomapproved file is missing? (Answer: scan succeeds, no governance annotations)
  - What happens when regulation pack signature is invalid? (Answer: pack rejected, previous version retained)
  - What happens when ComplianceDB is unreachable? (Answer: scan succeeds locally, cloud push queued)

### Gate 5: Security Confidence (>= 8/10)
- /cso threat model must pass with zero unmitigated HIGH-severity risks.
- CLI-specific vectors checked:
  - Command injection via unsafe os/exec arguments
  - File system permissions (insecure os.WriteFile modes)
  - Secret management (no hardcoded tokens, no secrets in shell history)
  - Path traversal in scan target resolution

### Gate 6: Test Coverage
- go test passes with zero failures.
- go vet clean.
- Golden fixture tests updated if output format changed.
- New features include positive AND negative test cases.

### Gate 7: Invariant Preservation
- go list -deps ./cmd/scan/... must not include net/http (zero network in scan).
- No auto_submit strings introduced (CI grep check).
- pkg/airom contains no non-stdlib imports.

### Gate 8: Release
- /ship successfully syncs with main, runs full test suite, and opens PR.
- PR description includes: what changed, why, acceptance criteria results.

---

## 3. Go CLI Adaptations (vs. Web App gstack)

gstack is web-app oriented. For AIROM Go CLI + cloud services:

| gstack Skill | Web App Usage | Go CLI Equivalent |
|---|---|---|
| /qa | Opens Chromium, clicks through UI flows | testscript golden file testing: compile binary, run real CLI commands in sandboxed dirs, match stdout/stderr/exit codes |
| /qa-only | Browser-based bug reporting | Run airom scan against fixture repos, diff output against expected golden files |
| /design-review | UI/UX audit with screenshots | Terminal output formatting review: table alignment, color codes, SARIF schema validation |
| /cso (OWASP) | XSS, CSRF, CORS, SQL injection | Command injection, file permissions, path traversal, secret leakage, unsafe deserialization |
| /benchmark | Page load times, Core Web Vitals | go test -bench, RSS memory profiling, scan time per 1000 files |
| /browse | Chromium browser automation | N/A for CLI; used for cloud dashboard testing only |
| /canary | Post-deploy monitoring | Post-release airom scan regression tests against known fixture repositories |

---

## 4. Sprint Ceremony Calendar (2-Week Cycle)

Week 1:
- Mon AM: Sprint Planning (/office-hours + /spec)
- Mon PM: Scope Lock (/plan-ceo-review)
- Tue: Architecture Lock (/plan-eng-review + /cso)
- Wed-Fri: Implementation

Week 2:
- Mon-Wed: Implementation continues
- Thu: Code Review (/review) + Integration Testing
- Fri AM: Release Engineering (/ship)
- Fri PM: Retrospective (/retro)

---

## 5. Feature Lifecycle Checklist

For EVERY feature shipped in the AIROM Compliance Platform:

- [ ] /office-hours pain framing completed
- [ ] /spec written and scored >= 7/10
- [ ] /plan-ceo-review scope locked (Expansion/Selective/Hold/Reduction)
- [ ] /plan-eng-review ASCII diagrams + test matrix + shadow paths
- [ ] /cso threat model >= 8/10 confidence, zero unmitigated HIGH risks
- [ ] Implementation complete with unit tests
- [ ] /review code review passed (auto-fixes applied, completeness verified)
- [ ] Golden fixture tests pass
- [ ] Invariant CI checks pass (zero network in scan, no auto_submit)
- [ ] /ship PR opened with acceptance criteria in description
