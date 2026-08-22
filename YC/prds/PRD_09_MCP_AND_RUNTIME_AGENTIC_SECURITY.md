# PRD-09: Model Context Protocol (MCP) & Runtime Agentic AI Security

> **Status:** READY FOR IMPLEMENTATION
> **Target Sprints:** Sprint 17 & Sprint 18 (Phase 7)
> **Target Directory:** `internal/detectors/mcp/`, `services/gateway/`, `internal/rules/agentic/`
> **Owner:** Lead AI Security & Systems Architect

---

## 1. Problem & Executive Objectives

- **Problem:** With the rapid adoption of Anthropic's Model Context Protocol (MCP) and multi-agent frameworks (LangGraph, CrewAI, AutoGen, Agno), static code scans alone cannot fully govern dynamic runtime tool invocation, autonomous sub-agent execution, prompt-injected tool hijacking, and runtime data exfiltration.
- **Solution:** A dual-engine approach:
  1. **Static MCP & Agentic Detector**: Discovers MCP servers, client handshakes, tool definitions, dynamic capabilities, and authorization boundaries in codebase and configuration files (`claude_desktop_config.json`, `mcp.json`, Python/TS SDKs).
  2. **AIROM Runtime Gateway / Reverse Proxy**: A lightweight, high-throughput Go proxy (`airom gateway`) that intercepts live outbound LLM/agent calls to enforce `.airomapproved` token/temperature caps, redact sensitive PII/secrets, and block unauthorized MCP tool executions in real-time.

---

## 2. Static MCP Detector Engine (`internal/detectors/mcp/`)

### 2.1 Detection Surface
- **Configuration Files:**
  - `claude_desktop_config.json`, `cline_mcp_settings.json`, `.cursor/mcp.json`, `mcp.config.json`
  - Scans for server commands, environment variables, exposed file paths, and external network host endpoints.
- **Source Code Bindings:**
  - Python: `mcp`, `fastmcp`, `mcp.server`, `mcp.client`
  - TypeScript / Node.js: `@modelcontextprotocol/sdk`, `@modelcontextprotocol/server-*`
  - Go: `github.com/mark3labs/mcp-go`
- **Output Claims:**
  - Component Kind: `framework` / `agentic-tool`
  - Properties: `mcp:transport` (stdio, sse, stream), `mcp:tools` (list of declared tool schemas), `mcp:resources`, `mcp:prompts`.

---

## 3. Dynamic Runtime Gateway & Interceptor (`services/gateway/`)

```
┌─────────────────┐       Outbound LLM Request      ┌──────────────────────────────────┐       Forward Request      ┌──────────────────┐
│  Agentic App /  │ ───────────────────────────────>│     AIROM RUNTIME GATEWAY        │ ─────────────────────────> │ OpenAI/Anthropic/│
│   MCP Client    │                                 │   • .airomapproved Check         │                            │ Bedrock Provider │
│                 │ <───────────────────────────────│   • PII & Secret Redaction Engine│ <───────────────────────── │                  │
└─────────────────┘       Sanitized Response        │   • Runaway Loop Rate Limiter    │       Provider Response    └──────────────────┘
                                                    │   • Audit & SIEM Telemetry Stream│
                                                    └──────────────────────────────────┘
```

### 3.1 Proxy Architecture & Gating Logic
1. **Model Whitelist & Parameter Gating:**
   - Evaluates incoming request against active `.airomapproved` manifest.
   - If model is unapproved: returns `HTTP 403 Forbidden` (`ErrShadowAIBlocked`).
   - If requested `temperature` or `max_tokens` exceeds approved ceiling: automatically clamps parameters to approved upper bound.
2. **Real-Time PII & Secret Redaction:**
   - Scans prompt content and tool inputs using high-speed regex/Aho-Corasick stream scanner.
   - Replaces SSNs, Credit Card numbers, AWS/API keys with `[REDACTED_PII]` or `[REDACTED_SECRET]` before transmission.
3. **Agentic Runaway Loop Circuit Breaker:**
   - Monitors recursive tool calls. If an agent executes > 25 consecutive tool calls within 60 seconds, trips the circuit breaker to prevent denial-of-wallet attacks.
4. **Audit Streaming:**
   - Emits cryptographically signed `AuditEvent` into ComplianceDB and external SIEM endpoints (Datadog, Splunk) for every intercepted transaction.

---

## 4. OWASP Top 10 for Agentic AI Integration

| OWASP Threat ID | Threat Category | AIROM Detection & Defense Mechanism |
| :--- | :--- | :--- |
| **ASI-01** | Agent Goal Hijacking | Runtime Gateway inspects system prompt integrity against golden hash. |
| **ASI-02** | Tool Execution Abuse | Static MCP scanner checks tool permissions; Gateway blocks unapproved tool calls. |
| **ASI-03** | Broken Boundary Control | Multi-tenant isolation verified in ComplianceDB and API Gateway. |
| **ASI-04** | Untrusted Code Execution | Scanner flags unsafe deserialization (`pickle`, `torch.load`) and dynamic eval. |
| **ASI-05** | Memory Poisoning | Gateway detects unverified context injections into vector DB stores. |
| **ASI-06** | Excessive Agency | Gateway enforces human-in-the-loop confirmation before executing destructive tools. |

---

## 5. Acceptance Criteria

- [ ] Static MCP detector recognizes stdio and SSE transport configs with 100% precision.
- [ ] `airom gateway` CLI command starts high-performance reverse proxy (< 2ms added latency).
- [ ] Gateway enforces parameter clamping and blocks unapproved models with `HTTP 403`.
- [ ] PII and secret redaction tested against 1,000+ adversarial prompt payloads with 0 leakage.
- [ ] Runaway loop circuit breaker halts runaway agent loops at 25 calls without panics.
