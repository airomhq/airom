# Track 4: AnomalyEngine & Policy-as-Code

> **Ownership:** Backend Systems Engineer  
> **Key Focus:** Rule-Based Diff Evaluation, Shadow AI Detection, Safety Parameter Drift, Regulatory Proximity Alarms.

---

## 1. Scope & Technical Objectives

1. **Zero Client Computation:** Scanner posts AIBOM diff; cloud evaluates anomaly rules in < 100ms.
2. **Rule-Based Diff Evaluation:** YAML-driven rules matching dded, modified, and 
emoved components.
3. **High-Risk Domain Proximity:** Flags AI added into sensitive code paths (hiring/, credit/, patient/).
4. **Deployment Flexibility:** Agentless CI webhooks by default; opt-in irom-agent daemon for enterprise.

---

## 2. Sprint Backlog & Epics (Months 1–6)

### Epic T4.1: Diff Engine & Core Anomaly Rules (Sprint 3–6)
- [ ] Cloud diff evaluator comparing incoming AIBOM vs previous git branch commit.
- [ ] Built-in rule: shadow-ai-detected (fires when component not in .airomapproved).
- [ ] Built-in rule: model-swap-detected (fires when model ID changes without PR approval).
- [ ] Built-in rule: config-drift-detected (fires on temperature / max_tokens exceeding permitted bounds).

### Epic T4.2: Sector-Specific Regulatory Proximity Rules (Sprint 5–8)
- [ ] proximity-hiring rule (NY LL144 / EEOC triggers).
- [ ] proximity-credit rule (ECOA / CFPB lending triggers).
- [ ] proximity-healthcare rule (HIPAA / FDA SaMD triggers).

### Epic T4.3: Enterprise Daemon (irom-agent) (Sprint 7–10)
- [ ] Lightweight Go daemon receiving GitHub/GitLab webhook push events.
- [ ] Fast-path partial scanning for modified files only.
- [ ] Direct push to cloud AnomalyEngine without waiting for CI build completion.

---

## 3. Definition of Done (DoD)
- Anomaly evaluation latency < 50ms per scan diff.
- Zero false positives on unchanged .airomapproved components.
- CLI outputs color-coded terminal alerts and sets exit code 1 on HIGH severity findings.
