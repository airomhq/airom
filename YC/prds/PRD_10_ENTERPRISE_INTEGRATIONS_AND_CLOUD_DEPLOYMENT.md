# PRD-10: Enterprise Ecosystem, CI/CD Integrations & Cloud Deployment

> **Status:** READY FOR IMPLEMENTATION
> **Target Sprints:** Sprint 19 & Sprint 20 (Phase 8)
> **Target Directory:** `.github/actions/airom-action/`, `deploy/helm/`, `deploy/docker/`, `sdks/`
> **Owner:** Lead Cloud Infrastructure & Developer Relations Engineer

---

## 1. Problem & Executive Objectives

- **Problem:** Enterprise customers require turnkey integrations with their existing CI/CD pipelines (GitHub Actions, GitLab CI), IT Service Management systems (Jira, ServiceNow), container orchestrators (Kubernetes, AWS ECS), and enterprise SDKs to embed AIROM governance into daily engineering workflows without friction.
- **Solution:** 
  1. **Official GitHub Action (`airomhq/airom-action@v1`)**: Zero-config GitHub Action publishing automated PR comments, check-runs, and SARIF security tab uploads.
  2. **Automated ITSM Ticket Dispatcher**: Automatic creation and synchronization of Jira / ServiceNow remediation tickets when compliance gaps or shadow AI are detected.
  3. **Enterprise SDKs (Python & TypeScript)**: Full-featured, type-safe client libraries for programmatic scanning, ledger querying, and attestation signing.
  4. **Production Cloud Infrastructure**: High-Availability Kubernetes Helm Chart, distroless multi-arch Docker images, Cosign container signing, and SOC 2 Type II audit hardening.

---

## 2. GitHub Action (`airomhq/airom-action@v1`) Specification

### 2.1 Action Configuration (`action.yml`)
```yaml
name: "AIROM Compliance & AI-BOM Scanner"
description: "Zero-config statutory AI compliance scanning, shadow AI detection, and SARIF security annotations for GitHub Actions."
branding:
  icon: "shield"
  color: "blue"

inputs:
  target:
    description: "Scan target path or repository directory"
    required: false
    default: "."
  compliance:
    description: "Comma-separated list of compliance frameworks (e.g., colorado-ai-act,nyc-ll144,eu-ai-act)"
    required: false
    default: "nist-ai-rmf,owasp-agentic,colorado-ai-act"
  fail-on:
    description: "Opt-in failure criteria (e.g., compliance:gap, shadow-ai)"
    required: false
    default: ""
  api-key:
    description: "AIROM Enterprise Cloud API Key for ComplianceDB ledger sync"
    required: false
  comment-on-pr:
    description: "Post automated compliance summary comment on pull requests"
    required: false
    default: "true"

runs:
  using: "docker"
  image: "docker://ghcr.io/airomhq/airom-action:v1"
```

### 2.2 Pull Request Summary Comment Output
The action posts an automated, collapsible Markdown comment on PRs:
```markdown
### 🛡️ AIROM AI Governance & Compliance Report

| Framework | Status | Met | Gap | Manual |
| :--- | :---: | :---: | :---: | :---: |
| **Colorado AI Act (SB 24-205)** | ⚠️ Gaps Detected | 2 | 1 | 2 |
| **NYC Local Law 144** | ✅ Passed | 2 | 0 | 2 |
| **EU AI Act (High-Risk)** | ⏳ Review Needed | 4 | 0 | 3 |

**Findings:**
* 🔴 `SHADOW_AI_DETECTED`: `pkg:pypi/anthropic@0.34.0` in `src/underwriting/scorer.py:14` (Not in `.airomapproved`)
* 🟡 `CONFIG_DRIFT_DETECTED`: `temperature=0.9` exceeds approved max `0.3`
```

---

## 3. ITSM Integration Engine (Jira & ServiceNow)

- **Trigger:** When ComplianceDB ingests a snapshot with new `gap` verdicts or `SHADOW_AI_DETECTED` anomalies.
- **Payload:** Dispatches webhook to Jira / ServiceNow REST API.
- **Features:**
  - Auto-assigns severity: High-Risk AI gaps -> Priority 1 (Blocker); Missing manual attestation -> Priority 3 (Medium).
  - Bidirectional sync: When Jira ticket is marked "Resolved", AIROM re-evaluates PR status on next commit.

---

## 4. Production Cloud Deployment & Kubernetes Helm Chart

```
deploy/
├── docker/
│   ├── Dockerfile.distroless          # Multi-stage minimal static binary container
│   ├── docker-compose.prod.yml        # High-availability production compose
│   └── nginx.conf                     # TLS termination & rate limiter
└── helm/
    └── airom-enterprise/
        ├── Chart.yaml
        ├── values.yaml                # Configurable replicas, Postgres HA, Redis, Ingress
        ├── templates/
        │   ├── deployment.yaml        # Stateless Enterprise Gateway deployment
        │   ├── service.yaml
        │   ├── ingress.yaml           # Ingress with cert-manager TLS
        │   ├── hpa.yaml               # Horizontal Pod Autoscaler (CPU/Mem based)
        │   ├── configmap.yaml
        │   └── secrets.yaml           # SealedSecrets / ExternalSecrets integration
```

---

## 5. Acceptance Criteria

- [ ] `airomhq/airom-action@v1` executes seamlessly on GitHub Actions with PR comments and SARIF uploads.
- [ ] Jira / ServiceNow webhook connector creates formatted remediation tickets upon gap detection.
- [ ] Python SDK (`pip install airom`) and TypeScript SDK (`npm i @airom/sdk`) published with typed client APIs.
- [ ] Kubernetes Helm Chart installs cleanly on minikube, EKS, and GKE with healthy liveness/readiness probes.
- [ ] Container images built, signed with Cosign, and verified with zero Critical/High CVEs.
