# PRD-07: Web Governance Dashboard & Human Attestation Gateway

> **Status:** READY FOR IMPLEMENTATION
> **Target Sprints:** Sprint 13 & Sprint 14 (Phase 5)
> **Target Directory:** `web/`, `services/server/`, `services/document/`
> **Owner:** Full-Stack & UI/UX Systems Lead

---

## 1. Problem & Executive Objectives

- **Problem:** While developers interact with AIROM via CLI in CI/CD, Enterprise Legal, Compliance, and Risk Officers lack an intuitive graphical interface to monitor real-time AI compliance posture, explore the cryptographic state ledger, audit shadow AI anomalies, and execute legally binding attestations on manual controls.
- **Solution:** A modern, high-performance web dashboard (`web/`) built with Next.js 15, TypeScript, Tailwind CSS, and Shadcn UI that connects directly to the Unified Enterprise Server Gateway (`services/server/`).
- **Core Objectives:**
  1. **Executive Compliance Cockpit**: Real-time aggregation of compliance status (Met / Gap / Manual) across all 8 supported state/federal/global frameworks for 1,000+ repositories.
  2. **Interactive Hash-Chain Ledger Visualizer**: Time-series graph of immutable snapshot blocks with client-side cryptographic SHA-256 validation and tamper detection.
  3. **Green / Yellow / Red Human Attestation Gateway**: Human-in-the-loop review portal enabling Compliance Officers to review code evidence, enter mandatory attestation text, and mint HMAC-signed approval tokens for regulator-ready reports.
  4. **Live Anomaly & Shadow AI Radar**: Server-Sent Events (SSE) stream for real-time alerting on unauthorized model swaps, parameter drift, and high-risk regulatory tripwires.

---

## 2. System Architecture & UI Component Hierarchy

```
web/
├── app/
│   ├── (auth)/
│   │   ├── login/page.tsx               # SSO (SAML/OIDC) & API Key login
│   │   └── layout.tsx
│   ├── (dashboard)/
│   │   ├── layout.tsx                   # App sidebar, org switcher, user menu
│   │   ├── page.tsx                     # Executive Compliance Cockpit
│   │   ├── repos/
│   │   │   ├── page.tsx                 # Repositories list & search
│   │   │   └── [id]/
│   │   │       ├── page.tsx             # Repository compliance overview
│   │   │       ├── ledger/page.tsx      # Hash-Chain Timeline & Block Inspector
│   │   │       ├── anomalies/page.tsx   # Shadow AI & Drift alerts
│   │   │       └── reports/page.tsx     # Statutory Report Generator & Review Screen
│   │   ├── frameworks/
│   │   │   └── [frameworkId]/page.tsx   # Framework deep-dive (CO, NYC, CA, EU AI Act)
│   │   ├── settings/
│   │   │   ├── team/page.tsx            # RBAC (Admin, Compliance Officer, Developer, Auditor)
│   │   │   ├── api-keys/page.tsx        # API Key generation & revocation
│   │   │   └── audit-log/page.tsx       # Immutable SOC 2 audit trail viewer
│   │   └── api/                         # Next.js BFF (Backend For Frontend) proxy
├── components/
│   ├── ui/                              # Shadcn UI primitives (Button, Dialog, Card, Table)
│   ├── charts/                          # Recharts/Visx compliance dials & radar charts
│   ├── ledger/
│   │   ├── HashChainGraph.tsx           # Interactive canvas/SVG blockchain visualizer
│   │   └── BlockDetailsModal.tsx        # Snapshot payload & Merkle proof viewer
│   ├── review/
│   │   ├── GreenYellowRedReview.tsx     # Human attestation review component
│   │   ├── EvidenceViewer.tsx           # Code snippet & AST citation drawer
│   │   └── AttestationSignModal.tsx     # HMAC token generation & signer block
│   └── anomaly/
│   │   └── AnomalyLiveFeed.tsx          # Real-time SSE alert notification stream
├── lib/
│   ├── api.ts                           # Typed API client for EnterpriseServer
│   ├── auth.ts                          # JWT Session & RBAC hook
│   └── crypto.ts                        # WebCrypto SHA-256 verification utilities
└── types/
    └── index.ts                         # Shared TypeScript interfaces
```

---

## 3. Detailed Component Specifications

### 3.1 Executive Compliance Cockpit (`app/(dashboard)/page.tsx`)
- **Key Metrics Cards:**
  - Total Monitored AI Assets (Models, Frameworks, Datasets, Vectors, Prompts)
  - Global Compliance Rate (% Met across all repositories)
  - Active Compliance Gaps (Urgent items requiring remediation)
  - Pending Human Attestations (Yellow controls needing signature)
- **Multi-Jurisdiction Radar:** Breakdown per framework (Colorado AI Act, NYC LL144, CA AB 2013, IL BIPA, TX TRAIGA, VA VCDPA, NIST AI RMF, OWASP Agentic).
- **Recent High-Severity Anomalies:** Real-time list of shadow AI discoveries.

### 3.2 Interactive Hash-Chain Ledger Visualizer (`components/ledger/HashChainGraph.tsx`)
- Displays sequential snapshot nodes: `Node(i) -> Hash(i) = SHA256(scanID | TS | aibomHash | controlsHash | prevHash)`.
- **Integrity Validation Action:** "Verify Ledger Integrity" button computes SHA-256 for all blocks in browser using `crypto.subtle.digest("SHA-256", ...)`.
- If bit-drift or parent hash mismatch is detected, turns node red with `TAMPER_DETECTED` banner and pinpointed block index.

### 3.3 Green / Yellow / Red Review Gateway (`components/review/GreenYellowRedReview.tsx`)
- **Green Controls (Automated - Met):** Collapsed view showing verified AST citations with file path and line range link. Read-only.
- **Yellow Controls (Manual - Attestation Required):** Interactive form requiring Compliance Officer to input legal justification, attach external policy URL or PDF, and provide electronic signature.
- **Red Controls (Gaps - Non-Compliant):** Displays missing required fields (e.g., missing impact assessment, unapproved model), estimated statutory fine tier, and suggested remediation steps.
- **Submit / Export Action:** Disabled until 100% of Yellow controls have valid attestations. When signed, generates HMAC token and outputs regulator-ready PDF/HTML report.

---

## 4. API & Real-Time SSE Contracts

### 4.1 Real-Time Anomaly Stream (`GET /api/v1/events/stream`)
- **Transport:** Server-Sent Events (`text/event-stream`).
- **Headers:** `Authorization: Bearer <jwt>`
- **Payload Example:**
```json
{
  "event": "anomaly_detected",
  "data": {
    "repo": "acme/loan-underwriter",
    "type": "shadow-ai",
    "severity": "HIGH",
    "component": "pkg:pypi/anthropic@0.34.0",
    "file": "src/underwriting/scorer.py:14",
    "timestamp": "2026-08-22T10:15:30Z"
  }
}
```

### 4.2 Attestation Minting (`POST /api/v1/repos/{repo}/attest`)
- **Request:**
```json
{
  "framework": "colorado-ai-act",
  "snapshot_id": "snap-98a72b",
  "signer_email": "sarah.legal@acme.com",
  "attestations": {
    "co.ai-act.risk-mgmt": "Audited under Enterprise NIST AI RMF policy v2.4",
    "co.ai-act.consumer-notice": "Implemented in frontend checkout UI via NoticeBanner.tsx"
  }
}
```
- **Response:**
```json
{
  "attestation_token": "hmac-sha256:8f9a2e3...",
  "signed_at": "2026-08-22T10:18:00Z",
  "report_url": "/api/v1/reports/export?token=8f9a2e3..."
}
```

---

## 5. Non-Functional & Security Requirements

1. **Zero Client Data Leakage:** Sensitive source code snippets are only rendered if the authenticated user possesses `auditor`, `compliance_officer`, or `admin` RBAC role.
2. **Sub-100ms UI Latency:** Local state caching using TanStack Query; hash-chain verification executes asynchronously in a Web Worker.
3. **Accessibility (WCAG 2.1 AA):** High-contrast color palette, full keyboard navigation, screen-reader aria attributes on all charts and tables.
4. **Offline Mode Support:** Standalone build mode allowing self-hosted enterprise deployment without external internet access.

---

## 6. Acceptance Criteria

- [ ] `web/` scaffolded with Next.js 15, Tailwind, and Shadcn UI with 100% TypeScript strict mode.
- [ ] Authentication works for SSO and API Keys against `EnterpriseServer`.
- [ ] Compliance Cockpit displays accurate Met/Gap/Manual metrics fetched from `/api/v1/orgs/{org}/compliance`.
- [ ] Ledger Explorer correctly validates 1,000+ snapshots and flags tampered blocks.
- [ ] Review Gateway generates valid HMAC attestation tokens and renders WCAG 2.1 AA compliant reports.
- [ ] Automated Jest / Playwright test suite passes with 100% success rate.
