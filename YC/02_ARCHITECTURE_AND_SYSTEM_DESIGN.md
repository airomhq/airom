# AIROM Compliance Platform — Architecture & System Design

---

## 1. System Overview & Physical Tiers

The AIROM Compliance Platform operates across three distinct tiers with an impenetrable trust boundary. Source code never leaves the client machine.

`
+==================================================================================+
|                            AIROM COMPLIANCE PLATFORM                             |
+==================================================================================+
|                                                                                  |
|  +----------------------------- CLIENT LAYER ---------------------------------+  |
|  |                                                                            |  |
|  |   airom-cli (Single static Go binary, CGO=0, 0 LLM, 0 network on scan)     |  |
|  |     - airom scan .            --> Generates AIBOM JSON locally             |  |
|  |     - airom report            --> Calls Cloud Report Engine (Opt-in)       |  |
|  |     - airom file              --> Calls Cloud Filing Agent (Opt-in)        |  |
|  |     - airom update            --> Pulls signed regulation packs            |  |
|  |                                                                            |  |
|  |   Local Regulation Store (~/.airom/packs/*.yaml)                           |  |
|  |   Verified via ed25519 signature before loading.                           |  |
|  |                                                                            |  |
|  |   DEPLOYMENT MODES:                                                        |  |
|  |     [Mode A: Agentless] (Default) -> GitHub Actions / CI/CD pipeline step. |  |
|  |     [Mode B: Agent] (Enterprise)  -> airom-agent background daemon.        |  |
|  +----------------------------------------------------------------------------+  |
|                                                                                  |
|  ============================== TRUST BOUNDARY ================================  |
|  | Crosses: AIBOM JSON (metadata only, signed with org API key)                |  |
|  | NEVER Crosses: Source code, weights, proprietary dataset contents, secrets   |  |
|  ==============================================================================  |
|                                                                                  |
|  +----------------------------- UPDATE CHANNEL -------------------------------+  |
|  | updates.airom.dev (CDN) -> Daily ed25519-signed regulation & rule bundles.  |  |
|  | Binary releases and regulation updates are FULLY DECOUPLED.                 |  |
|  +----------------------------------------------------------------------------+  |
|                                                                                  |
|  +------------------------------ CLOUD LAYER ---------------------------------+  |
|  |                                                                            |  |
|  |  [RegWatch Service]                                                        |  |
|  |    * Scrapes 50 state legislature portals + federal agencies (FTC/SEC).     |  |
|  |    * Server-side LLM parses statutes -> structured controls.               |  |
|  |    * Human compliance expert review gate -> Signs with ed25519 key.        |  |
|  |                                                                            |  |
|  |  [Anomaly Engine]                                                          |  |
|  |    * Compares current AIBOM vs previous snapshot in ComplianceDB.          |  |
|  |    * Pure YAML-rule-based diff checking (Shadow AI, Model Swap, Drift).    |  |
|  |                                                                            |  |
|  |  [Report Engine]                                                           |  |
|  |    * Evidence-anchored LLM report generation (PDF, HTML, Word, Markdown).  |  |
|  |    * Every sentence verified against [ev:...] citations. Ephemeral memory. |  |
|  |                                                                            |  |
|  |  [Filing Agent]                                                            |  |
|  |    * Pre-populates state filings using Green/Yellow/Red validation.        |  |
|  |    * Submit button requires human confirmation token (90s TTL).            |  |
|  |    * Immutable PostgreSQL append-only audit log.                           |  |
|  +----------------------------------------------------------------------------+  |
|                                                                                  |
|  +------------------------- ON-PREM OPTION (Enterprise) ----------------------+  |
|  | docker run airom/report-engine:latest (Bring-Your-Own-LLM: Azure/Ollama).   |  |
|  +----------------------------------------------------------------------------+  |
+==================================================================================+
`

---

## 2. Core Scanner Pipeline (Invariants & Mechanics)

The core scanner in C:\Users\remoteadmin\airom is designed with 8 CI-enforced invariants:
1. **Read-Once:** Each file byte is streamed once into a shared memory buffer.
2. **Bounded Memory:** Peak RSS is O(1) relative to repo size (32KB header sampling + Aho-Corasick prefilter).
3. **Decide-Before-Read:** Path, extension, and magic-byte routing skips 95%+ of irrelevant files before read.
4. **Detectors Emit Claims Only:** Identity and deduplication belong solely to the Assembler.
5. **Writers Are Pure Functions:** Output formatting (*Inventory -> []byte) has zero side effects.
6. **Degradable:** File read errors degrade to Unknown components; scans never panic or abort.
7. **Deterministic Output:** Bit-identical outputs regardless of CPU concurrency or OS.
8. **Pure Go / CGO=0:** Statically linked binary, zero dynamic C libraries, cross-platform.

---

## 3. Data Flow & Boundary Security

| Data Type | Physical Location | Boundary Crossing Policy |
|---|---|---|
| Source Code (.py, .ts, .go) | Local Developer/CI disk | **NEVER** |
| Model Weights (.safetensors, .gguf) | Local disk / Object storage | **NEVER** |
| ibom.json (Components, Locations, Hashes) | Local disk (Canonical) | **Explicit user action only** (e.g. irom report) |
| Regulation Rule Packs | CDN / Local cache | **One-way ingress** (CDN -> Client) |
| Generated Audit Reports | Memory / Client output directory | Returned directly to client |
| Filing Audit Logs | Append-only Cloud Store | Org-authenticated access only |

---

## 4. Layer Deep Dives

### 4.1 Layer 1: RegWatch (Regulatory Radar)
- Crawls state legislative feeds (LegiScan, state portals).
- Normalizes statutory text into structured YAML definitions (.airom-regpack.yaml).
- Features a mandatory **Human Expert Gate** before signing and publishing.

### 4.2 Layer 2: ComplianceDB (Continuous Time-Series Ledger)
- Maps organizational multi-repo hierarchies to regulatory obligations.
- Produces tamper-evident hash-chained snapshot trees: self_hash = SHA256(scan_id + timestamp + aibom_hash + controls + prev_hash).
- Tracks compliance incident lifecycles (CONTROL_MET -> CONTROL_GAP -> INCIDENT_OPEN -> INCIDENT_RESOLVED).

### 4.3 Layer 3: AnomalyEngine (Policy-As-Code)
- Rule-based diff evaluation on each scan delta against .airomapproved.
- Detects Shadow AI, Model Swapping, and Configuration Drift (e.g. temperature > approved max).

### 4.4 Layer 4: ReportEngine (Evidence-Anchored Prose)
- Zero hallucination guarantee: every assertion requires an [ev:...] anchor back to the AIBOM.
- Generates PDF, HTML, DOCX, and Markdown formats.

### 4.5 Layer 5: FilingAgent (Human-In-The-Loop Workflow)
- Pre-fills state filing forms.
- Enforces the **Green/Yellow/Red** review gate.
- Submit button is strictly human-activated via a 90-second HMAC token.
