# Project status and positioning

The honest ledger of what AIROM does today, what it deliberately does not do,
and how it compares to adjacent tools. Kept here rather than in the README so
the front page stays short.

## Project status

AIROM is at **v0.3.6**: feature-complete against the 10-phase plan, architecture through a multi-agent production review, with three overlays (artifact risk, CVE, model lifecycle), compliance mapping, test-scope filtering, per-PR AIBOM diffing, lockfile and installed-metadata version resolution, PyInstaller archive reading, SQL/DDL scanning, SPDX 3.0.1 and OpenVEX export, and a signed rule-update channel — now checked automatically, once a day, outside CI — added on top. Early software — expect rough edges, and see the deferred row below for what it deliberately does not do yet. Honest ledger:

| Area | Status |
|---|---|
| Architecture, domain model, decision log ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) | **Complete** — accepted v1 baseline |
| Repository scaffolding on the §4 layout (packages and their contracts, build files, docs) | **Complete** |
| CLI ([docs/cli.md](docs/cli.md)): scan/fs/repo/image/k8s/clean/version, config layering (flags > env > file > defaults), exit-code contract, `--fail-on` grammar, pprof/trace bootstrap | **Complete**, plus grouped/styled help and a live scan progress indicator that degrades to nothing off a terminal |
| Filesystem scanner: dir source (nested `.gitignore`/`.airomignore` stack, default skips, symlink safety), classification (language/binary/magic), read-once tee-hashed file context, phase-1 streaming pipeline (bounded channels, clamped I/O budget, panic isolation, deterministic output) | **Complete** |
| Plugin framework: public SDK (`pkg/airom` domain graph with tri-state fields, `pkg/airom/detect` contracts + dispatch index, `purl` discipline, `detectortest` harness), dispatcher with per-detector isolation and accounting, explicit catalog + Syft-style `--select`, assembler (CanonicalKey identity, keep-and-relate merge, grouped noisy-OR confidence, refusal-first relations), rule-engine compiler (full [rule-schema.md](docs/rule-schema.md) lint contract, three-layer merge, self-invalidating ruleset hash, Aho–Corasick prefilter, region lexers for all 8 languages), `detectors-gen`, `airom detectors list/explain` | **Complete** `airom fs . --rules pack.yaml` runs user rule packs end-to-end today |
| Detectors & rule packs: binary model-file parsers (GGUF, safetensors, ONNX, Torch, SavedModel, TFLite, HDF5, TensorRT — fuzzed) with an artifact-risk overlay (pickle imports, Keras Lambda, GGUF template gadgets, SavedModel PyFunc → CycloneDX `vulnerabilities[]`/SARIF), 8-ecosystem manifest detectors plus lockfile (npm/yarn/pnpm/poetry/uv/pipenv) and installed-metadata (`.dist-info`/`.egg-info`) version resolution, Go AST detector, prompt/dataset/infra detectors, phase-2 project detectors (HF-dir assembly, adapter lineage, config binding, RAG synthesis), 61 embedded rule packs / 129 rules across 9 categories (incl. a `security` category and a rule-level `risk:` field), `rules list/lint/test` + `dev` scaffolding | **Complete** Scans a real AI project into a rich AIBOM (models, embeddings, vector DBs, frameworks, weights, prompts, infra, RAG pipelines) |
| Sources: `repo` (exec-git shallow clone + local worktrees), `image` (docker-save/OCI archive + OCI layout — live registry/daemon pull is a follow-up), `k8s` (offline `--manifests` image enumeration — live cluster is a follow-up) | **Complete** (with the noted follow-ups) |
| Writers: native JSON (versioned, lossless superset — round-trip tested), CycloneDX 1.6/1.7 ML-BOM (modelCard + `evidence.occurrences[]` + `vulnerabilities[]` for risks + `definitions`/`declarations` for compliance, validated against the official schemas), SARIF 2.1.0 (one rule per detector/risk, one result per occurrence, line-free fingerprints), YAML, a Markdown compliance report, OpenVEX 0.2.0, SPDX 3.0.1 JSON-LD (AI/Dataset/Software/Security profiles, `NOASSERTION` discipline on required fields), table; multi-output `-o fmt=path` | **Complete** `airom scan . -o cyclonedx=bom.json -o spdx=bom.spdx.json` emits both from one pass |
| Compliance mapping (`--compliance`): AIBOM → governance-framework controls (met/gap/manual, no fabricated scores), projected as CycloneDX attestations + a Markdown report, gateable via `--fail-on compliance:gap`. Frameworks: NIST AI RMF 1.0, OWASP Agentic AI ([docs/compliance.md](docs/compliance.md)) | **Complete** — evidence-linked, deterministic, offline |
| CVE overlay (on by default, `--no-cve`): the AI packages AIROM inventoried, queried against OSV.dev, into CycloneDX `vulnerabilities[]` / SARIF / a Trivy-style detail table, with a locally computed CVSS score, a version-aware fixed-in, and a fail-closed `--fail-on cve` gate ([docs/cve.md](docs/cve.md)) | **Complete** — the only overlay that needs the network; refuses under `--offline` rather than reporting a quiet nothing |
| Model lifecycle / EOL overlay (on by default, `--no-eol`): hosted models matched against a curated catalog of provider retirement announcements — every claim dated and sourced, none inferred from naming, gateable via `--fail-on eol` ([docs/eol.md](docs/eol.md)) | **Complete** — offline; a model the catalog does not cover carries **no claim**, never a quiet "supported" |
| AIBOM diff (`airom diff <old> <new>`): the semantic delta between two native documents — added / removed / changed, keyed by stable component ID, with the risk, CVE, and lifecycle overlays on the rows. `table`/`markdown`/`json`, gateable via `--fail-on` over added and changed only ([docs/cli.md](docs/cli.md)) | **Complete** — refuses to gate when the two documents came from different tooling, rather than blaming a PR for a rule change |
| Signed rule-update channel (`airom rules update`): ed25519-verified bundles from [airomhq/airom-rules](https://github.com/airomhq/airom-rules) carrying rule packs and lifecycle catalogs, so detection and retirement dates refresh without a new binary; every AIBOM records `rulesVersion` + `rulesHash` + `eolCatalog` ([docs/cli.md](docs/cli.md)) | **Complete** — the only network path outside `--cve`; scans themselves never fetch |
| Test suite: golden end-to-end fixture repos through the whole pipeline into every format, official CycloneDX/SARIF schema conformance, `docs/mapping.md` round-trip enforcement, full-scan determinism (`--parallel 1` vs `16`), chaos degradation, and a P2 RSS-ceiling regression harness — everything under `-race`, ~74% coverage | **Complete** |
| Release automation: CI (lint/vet/gofmt, `-race` tests on Linux+macOS, `CGO_ENABLED=0` cross-compile matrix for all six targets, generated-code drift check, fuzz smoke, CodeQL), goreleaser (static matrix builds, checksums, keyless cosign signing, per-release SBOM + self-scanned AIBOM), Dependabot, issue/PR templates, `SECURITY.md`/`CODE_OF_CONDUCT.md`/`CONTRIBUTING.md` | **Complete** |
| Production hardening: whole-tree adversarial review (10 dimensions, per-finding verification) that found and fixed 17 verified defects — an OCI-layout path-traversal escape, a static-pickle scan evasion via memo/GET, the unwired `--fail-on` CI gate, a P7 stack-trace leak, YAML int64 corruption, non-canonical purls, and detector/rule-prefilter gaps — each with a regression test. Confirmed the empty CycloneDX `dependencies[]` (no substantiated `depends-on` edges) and the deferred live registry/daemon/cluster modes (fail cleanly) are deliberate, not defects | **Complete** |
| Attestation verification, per-layer attribution, OCI rule registry, live-cluster/registry source modes, root→dependency edge synthesis | Deferred to v2 by design (reserved slots — see [ARCHITECTURE §16](docs/ARCHITECTURE.md)) |

Known gaps, each surfaced in the affected flag's own `--help` rather than only here: caching is not implemented (every scan is cold, `--no-cache` is a no-op), live registry/daemon image pulls are not available (use `airom image --input <archive>`), and live-cluster scanning is not available (use `airom k8s --manifests <dir>`).


## Comparison

No FUD, just positioning — the tools below solve different problems:

| | AIROM | Registry-centric AIBOM generators | Proprietary AI security scanners |
|---|---|---|---|
| Input | **Your repo, image, or cluster** | A registry entry you name (e.g. an HF repo) | Varies; often model artifacts or SaaS-connected repos |
| Answers "why is this in my AIBOM?" | **Yes — file:line occurrences, technique, confidence in the BOM** | No — output describes the model, not your usage of it | Typically findings without BOM-native evidence |
| CycloneDX `evidence.occurrences[]` | **Emitted** | Not emitted | Not emitted |
| Load-time risk detection | **Built in — pickle / Lambda / template / PyFunc / unsafe-load, as CycloneDX `vulnerabilities[]` + SARIF, offline** | No | Varies — some scan model artifacts, typically SaaS or agent-based |
| Known-CVE overlay | **On by default — AI deps matched against OSV.dev with real CVSS v3 scores, into the same `vulnerabilities[]`/SARIF; `--no-cve` for offline/reproducible** | Rarely | Sometimes, usually as the core product |
| Compliance mapping | **Evidence-linked — NIST AI RMF / OWASP Agentic as CycloneDX attestations, honest about what a scan can't verify** | No | Sometimes, but without BOM-native evidence |
| Coverage | Hosted APIs **and** local weights **and** frameworks, vector DBs, prompts, datasets, params, infra, RAG graphs | The named model | Usually model files and/or a curated subset |
| Distribution | Single static Go binary, offline-capable | Python package | Agent or SaaS |
| License | Apache 2.0 | Varies (often open source) | Proprietary |

If you already know exactly which registry model you use and want its card, a registry-centric generator is the right tool. AIROM is for when the ground truth is your codebase and you have to prove it.

