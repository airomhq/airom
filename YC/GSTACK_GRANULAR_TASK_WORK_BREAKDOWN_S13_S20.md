# AIROM Enterprise Platform — Granular Task Work Breakdown (Sprints 13–20)

> **Document Standard:** Atomic, measurable, ticket-by-ticket engineering task breakdown for Phase 5 through Phase 8.

---

## Track 5: Web Governance Dashboard & Attestation Gateway (Sprints 13–14)

### Task 5.1.1: Next.js 15 & UI Primitive Foundation
- **File:** `web/package.json`, `web/tsconfig.json`, `web/tailwind.config.ts`, `web/components/ui/`
- **Scope:** Initialize Next.js 15 App Router, TypeScript strict mode, Tailwind CSS v4, Lucide icons, and Shadcn UI primitives.
- **Unit Tests:** `npm run test` executes component snapshot tests.

### Task 5.1.2: Enterprise SSO & API Key Authentication Flow
- **File:** `web/app/(auth)/login/page.tsx`, `web/lib/auth.ts`
- **Scope:** JWT cookie management, API Key bearer token storage, RBAC hook (`useRole()`) enforcing Admin, Compliance Officer, Developer, and Auditor role views.

### Task 5.1.3: Executive Compliance Cockpit
- **File:** `web/app/(dashboard)/page.tsx`, `web/components/charts/ComplianceDial.tsx`
- **Scope:** Connect to `GET /api/v1/orgs/{org}/compliance`, render Met/Gap/Manual dials, multi-state radar, and high-risk gap alerts.

### Task 5.2.1: Interactive Hash-Chain Visualizer
- **File:** `web/components/ledger/HashChainGraph.tsx`, `web/lib/crypto.ts`
- **Scope:** Time-series SVG block explorer. "Verify Integrity" button triggers Web Worker computing SHA-256 over all snapshot hashes, highlighting tampered blocks in red.

### Task 5.2.2: Green / Yellow / Red Attestation Review Portal
- **File:** `web/components/review/GreenYellowRedReview.tsx`, `web/components/review/EvidenceViewer.tsx`
- **Scope:** Form for manual control sign-offs. Connects to `POST /api/v1/repos/{repo}/attest` to generate HMAC-signed attestation tokens.

### Task 5.2.3: Real-Time SSE Anomaly Stream
- **File:** `web/components/anomaly/AnomalyLiveFeed.tsx`
- **Scope:** Connects to `GET /api/v1/events/stream` via EventSource, shows real-time toast notifications on shadow AI or config drift.

---

## Track 6: EU AI Act & Global Regulatory Harmonization (Sprints 15–16)

### Task 6.1.1: EU AI Act (Regulation (EU) 2024/1689) Compliance Spec
- **File:** `internal/compliance/specs/eu-ai-act.yaml`
- **Scope:** Complete statutory mapping for Title II (Prohibitions), Title III (High-Risk AI), and Title VIII (GPAI transparency & copyright).

### Task 6.1.2: Statutory EU Technical Documentation Generator (Annex IV)
- **File:** `services/report/eu_ai_act.go`, `services/report/eu_ai_act_test.go`
- **Scope:** Generates Annex IV compliant technical documentation in WCAG 2.1 AA HTML and statutory Markdown.

### Task 6.2.1: ISO/IEC 42001 (AIMS) & Canadian AIDA Compliance Specs
- **File:** `internal/compliance/specs/iso-42001.yaml`, `internal/compliance/specs/canada-aida.yaml`
- **Scope:** Author clause-by-clause requirements for AI Management Systems and Canadian federal transparency.

### Task 6.2.2: Global Multi-Standard Harmonization Engine
- **File:** `internal/compliance/harmonize.go`, `internal/compliance/harmonize_test.go`
- **Scope:** Cross-maps common evidence across multiple jurisdictions so 1 code scan satisfies CO, NYC, CA, EU, and ISO simultaneously.

---

## Track 7: Model Context Protocol (MCP) & Runtime AI Security (Sprints 17–18)

### Task 7.1.1: Static Model Context Protocol (MCP) Detector
- **File:** `internal/detectors/mcp/detector.go`, `internal/detectors/mcp/detector_test.go`
- **Scope:** Parses `claude_desktop_config.json`, `mcp.json`, Python/TS SDK imports, extracting tool schemas, transport modes, and endpoints.

### Task 7.1.2: OWASP Agentic Top 10 Automated Rulepack
- **File:** `rules/packs/owasp_agentic_top10.yaml`
- **Scope:** Detects unconstrained tool access, dynamic code execution, and unverified memory injections.

### Task 7.2.1: High-Performance Go Runtime Gateway Proxy
- **File:** `services/gateway/proxy.go`, `cmd/airom/gateway.go`
- **Scope:** Reverse-proxy intercepting outbound LLM traffic. Blocks unapproved models (`HTTP 403`) and clamps temperature/token parameters to `.airomapproved` ceilings.

### Task 7.2.2: Streaming PII & Secret Redaction Engine
- **File:** `services/gateway/redact.go`, `services/gateway/redact_test.go`
- **Scope:** Regex and token stream scanner replacing SSNs, Credit Cards, and API keys with `[REDACTED]` in sub-millisecond time.

### Task 7.2.3: Agentic Runaway Loop Circuit Breaker
- **File:** `services/gateway/circuit_breaker.go`
- **Scope:** Rate-limiter tracking recursive tool call bursts, halting loops at >25 calls/min.

---

## Track 8: Enterprise CI/CD, Cloud Deployment & Launch (Sprints 19–20)

### Task 8.1.1: Official GitHub Action (`airomhq/airom-action@v1`)
- **File:** `.github/actions/airom-action/action.yml`, `.github/actions/airom-action/entrypoint.sh`
- **Scope:** Docker-based GitHub Action running scans, posting formatted PR summary comments, and uploading SARIF reports.

### Task 8.1.2: Jira & ServiceNow Bi-Directional Webhook Connector
- **File:** `services/server/itsm_webhook.go`
- **Scope:** Dispatches formatted issue tickets on compliance gaps and auto-resolves when remediated in subsequent scans.

### Task 8.1.3: Enterprise Python & TypeScript SDKs
- **File:** `sdks/python/airom/client.py`, `sdks/typescript/src/index.ts`
- **Scope:** Type-safe programmatic client libraries for ComplianceDB ledger queries and scan orchestration.

### Task 8.2.1: Production Multi-Arch Docker Container & Cosign Signing
- **File:** `deploy/docker/Dockerfile.distroless`, `.github/workflows/docker-publish.yml`
- **Scope:** Builds minimal distroless image (< 30MB) signed with Cosign / Sigstore.

### Task 8.2.2: High-Availability Kubernetes Helm Chart
- **File:** `deploy/helm/airom-enterprise/Chart.yaml`, `deploy/helm/airom-enterprise/templates/`
- **Scope:** Production Helm chart supporting HPA autoscaling, HA Postgres, Redis caching, and Ingress TLS.

### Task 8.2.3: SOC 2 Type II Compliance & v1.0.0 Release Finalization
- **File:** `docs/SOC2_READINESS.md`, `docs/RELEASING.md`
- **Scope:** SOC 2 control mappings, production release verification, and v1.0.0 release sign-off.
