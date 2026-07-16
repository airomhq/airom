# Security Policy

AIROM is a security tool: it reads untrusted inputs (arbitrary files, git
repositories, container image layers, Kubernetes manifests) and parses binary
formats. We take vulnerabilities in it seriously.

## Supported versions

AIROM is pre-1.0. Security fixes land on `main` and in the latest tagged
release. Until 1.0, only the most recent release is supported.

| Version | Supported |
| ------- | --------- |
| latest release | ✅ |
| older releases | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub Security Advisories:

- Go to the [Security tab](https://github.com/Roro1727/airom/security/advisories/new) and open a draft advisory, **or**
- email **rohan872784@gmail.com** with the details.

Please include:

- the affected version (`airom version`) and platform,
- a description of the issue and its impact,
- a minimal input that reproduces it (a crafted file, image, or manifest — the smaller the better), and
- any proof-of-concept or stack trace you have.

### What to expect

- We aim to acknowledge a report within **3 business days**.
- We'll confirm the issue, determine affected versions, and keep you updated as we work on a fix.
- We'll credit you in the advisory unless you'd prefer to remain anonymous.
- We ask that you give us a reasonable window to release a fix before any public disclosure (coordinated disclosure).

## Threat model, briefly

AIROM's inputs are **untrusted by design** — you point it at code and
artifacts you don't control. The things we care most about:

- **Parser safety.** Binary format parsers (model files, image layers) must not
  panic, exhaust memory, or read out of bounds on malformed input. These are
  fuzzed (`make fuzz`); new crashers are regressions.
- **Bounded resources.** A hostile input must not cause unbounded memory or
  disk use. Reads are size-capped and streamed (invariants P1–P2 in
  `docs/ARCHITECTURE.md`).
- **No code execution.** AIROM never executes, imports, or evaluates the code
  it scans. It reads bytes and matches evidence.
- **Path containment.** Traversal, symlink escape, and archive/zip-slip style
  inputs must not let a scan read or write outside its intended root.

Findings that let a crafted input escape any of these bounds are in scope and
valued.
