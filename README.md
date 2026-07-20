# AIROM

**Open-source AI Bill of Materials (AIBOM) scanner.**

AIROM is an open-source scanner that discovers AI assets — including models, prompts, datasets, embeddings, vector databases, and AI frameworks — and generates AI Bills of Materials (AIBOMs). It runs as a single static binary over a filesystem, source repository, container image, or Kubernetes cluster, and puts `file:line` evidence behind every entry.

[![CI](https://github.com/airomhq/airom/actions/workflows/ci.yml/badge.svg)](https://github.com/airomhq/airom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/airomhq/airom?include_prereleases)](https://github.com/airomhq/airom/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/airomhq/airom)](https://goreportcard.com/report/github.com/airomhq/airom)
[![Go Reference](https://pkg.go.dev/badge/github.com/airomhq/airom.svg)](https://pkg.go.dev/github.com/airomhq/airom)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **v0.1.0 — first release.** Early but real: the pipeline, detectors, rule packs, and all five writers are implemented and tested. See [Project status](#project-status) for the honest ledger of what ships today versus what is deferred.

---

## What is AIROM?

Sooner or later, an auditor, a customer, or your own security team asks the question:

> *"Your AIBOM says this service uses `gpt-4.1`. **Why?** Where, exactly?"*

Most AIBOM tools can't answer it. They are registry-centric — you name a model on Hugging Face, they render a model card — or they are proprietary and never look at your code at all. Nobody scans *the repository you actually ship* and shows their work.

AIROM is **evidence-first**. Every component in the output carries:

- **Occurrences** — `file:line`, matched snippet, and enclosing symbol for every sighting
- **Detection technique** — source-code analysis, binary header parse, manifest analysis, hash comparison, …
- **A calibrated confidence score** — with the arithmetic behind it, not a vibe

That evidence is emitted as CycloneDX 1.6 `evidence.identity[]` + `evidence.occurrences[]` — a spec-native home for "seen at file:line, by technique T, with confidence C" that **AIBOM tools routinely leave empty** — plus a SARIF projection so the same findings land as annotations in GitHub Code Scanning. One scan, one graph, every format a pure projection of it.

> **How it relates to SBOM tooling.** An SBOM scanner inventories software packages to produce an SBOM; AIROM inventories AI-specific assets — models, datasets, prompts, vector stores, serving infrastructure — to produce an AIBOM. It is the AI-asset counterpart to software-dependency scanning, its own tool with its own problem space.

## What AIROM detects

| Category | Coverage |
|---|---|
| **Hosted model APIs** | OpenAI, Anthropic, Gemini, AWS Bedrock, Azure OpenAI, Cohere, Mistral, Groq, Ollama — model-ID literals and SDK call sites |
| **Local model weights** | GGUF, safetensors, ONNX, Torch (pickle-zip), TensorFlow SavedModel, TensorRT, TFLite, HDF5 — magic bytes + header metadata (architecture, parameter count, quantization), never loaded or executed |
| **Model directories & lineage** | Hugging Face model dirs (`config.json` + weights = one component), PEFT/LoRA adapters → `derived-from` base-model edges |
| **Embedding models** | OpenAI, sentence-transformers, BGE/E5/MiniLM, Voyage, Cohere — hosted or local |
| **Frameworks & SDKs** | LangChain, LlamaIndex, Haystack, DSPy, CrewAI, AutoGen, Semantic Kernel, Transformers, vLLM, MLflow, and the provider SDKs — from manifests *and* usage |
| **Vector databases** | Chroma, Milvus, Qdrant, Pinecone, Weaviate, FAISS, pgvector, Redis, Elasticsearch, MongoDB Atlas |
| **Prompts** | Prompt files (txt/md/yaml/jinja), `PromptTemplate`/`ChatPromptTemplate`/`system_prompt` patterns |
| **Datasets** | CSV/JSONL/Parquet/Arrow signatures, `load_dataset()`, Kaggle and HF dataset references |
| **Generation parameters** | temperature, top_p, top_k, max_tokens, seed, stop, reasoning effort, response format — bound to the model at the call site, with provenance |
| **Serving infrastructure** | Ollama, vLLM, TGI, Ray Serve, SageMaker, Vertex AI, Azure ML — including Dockerfile/compose/k8s manifests |
| **RAG pipelines** | Retriever + vector store + embedder + LLM stitched into a synthesized `rag-pipeline` composite with typed, evidenced edges |

**Scan targets:** filesystem · git repository (local or URL) · container image (`--input` tarball or OCI layout today; remote/daemon pull is a follow-up) · Kubernetes workloads (offline `--manifests` today; live-cluster is a follow-up)

**Languages:** Python, JavaScript, TypeScript, Go, Java, Rust, C#, Kotlin

**Output formats:** native AIBOM JSON (versioned schema) · CycloneDX 1.6 ML-BOM · SARIF 2.1.0 · YAML · table — any combination in one scan. SPDX 3.0.1 AI profile is a reserved v2 slot.

## Quick start

### Install

```bash
# pip — no Go toolchain needed. Installs the `airom` command AND the Python SDK.
pip install airom        # or: pipx install airom  (isolated, always on PATH)

# From source (requires Go 1.25+). Resolves to the newest release tag.
go install github.com/airomhq/airom/cmd/airom@latest
```

Then `airom --version` should work from any directory.

<details>
<summary><b><code>airom: command not found</code>?</b> — it's on PATH, or it isn't.</summary>

The wheel installs `airom` into your environment's `bin/`, so **pip** puts it on PATH
automatically inside an active virtualenv (`pipx` does so globally). **`go install`**
writes to `$(go env GOPATH)/bin`, which Go does *not* add to PATH for you:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"     # add to ~/.zshrc or ~/.bashrc
```

Check where it went with `command -v airom`, `pip show -f airom`, or `go env GOPATH`.
</details>

Prebuilt, cosign-signed binaries for all six targets are on the [releases page](https://github.com/airomhq/airom/releases), each with a checksum and an SBOM; a Homebrew tap is planned. AIROM releases as a single static binary (`CGO_ENABLED=0`) — no runtime, no dependencies.

### Scan

```bash
# Auto-detect the target: directory, git URL, or image reference
airom scan .

# Explicit nouns — one subcommand per target type
airom fs ./my-service
airom repo https://github.com/org/rag-app
airom image --input img.tar          # docker save -o img.tar nginx:latest
airom k8s --manifests ./deploy       # offline: enumerate workload images

# Multiple outputs from one scan: table to the terminal,
# CycloneDX and SARIF to files
airom scan . -o table -o cyclonedx=bom.json -o sarif=scan.sarif

# Narrow the detector set; add your own rules
airom scan . --select "rules,+modelfile/gguf,-dataset/file" --rules extra.yaml
```

**Exit codes:** `airom` exits **0 when the scan succeeds — findings are not failures**. Gating is opt-in CI policy:

```bash
airom scan . --exit-code 1 --fail-on "local-model-file&confidence>=0.9"
```

## Example output

```
$ airom scan .

AI Bill of Materials — /home/you/my-ai-app
7 component(s), 3 relationship(s)

KIND              NAME                         VERSION   PROVIDER   CONF   EVIDENCE
hosted-llm        gpt-4.1                      -         openai     0.87   12 occ
embedding-model   text-embedding-3-large       -         openai     0.85   3 occ
local-model-file  llama-3-8b-instruct.Q4_K_M   -         local      0.97   2 occ
framework         langchain                    0.3.14    -          0.95   2 occ
vector-db         chromadb                     0.6.3     -          0.92   4 occ
prompt            system-prompt.md             -         local      0.80   1 occ
rag-pipeline      rag-pipeline#1               -         -          0.78   0 occ
```

And the answer to the auditor's question, in the CycloneDX BOM (abridged):

```jsonc
{
  "type": "machine-learning-model",
  "bom-ref": "airom:1f3a9b2c4d5e6f70",
  "group": "openai",
  "name": "gpt-4.1",
  "modelCard": { "modelParameters": { "task": "text-generation" } },
  "properties": [
    { "name": "airom:model.provider", "value": "openai" },
    { "name": "airom:model.id", "value": "gpt-4.1" },
    { "name": "airom:confidence", "value": "0.87" },
    { "name": "airom:param.temperature", "value": "0.2 @ src/rag.py:88" }
  ],
  "evidence": {
    "identity": [
      {
        "field": "name",
        "confidence": 0.87,
        "methods": [
          { "technique": "source-code-analysis", "confidence": 0.85,
            "value": "model=\"gpt-4.1\"" }
        ]
      }
    ],
    "occurrences": [
      { "location": "src/rag.py", "line": 88, "symbol": "answer_question",
        "additionalContext": "client.chat.completions.create(model=\"gpt-4.1\", temperature=0.2)" },
      { "location": "src/summarize.py", "line": 41, "symbol": "summarize" }
      // …10 more
    ]
  }
}
```

Note what's *not* there: no fabricated `pkg:generic/openai/gpt-4.1` purl. Hosted API models aren't packages; AIROM identifies them via `bom-ref` and namespaced properties rather than polluting purl-keyed consumers like Dependency-Track. Local weight files, by contrast, get real purls (`pkg:huggingface/...`, `pkg:generic?checksum=...`) and SHA-256 hashes — their identity **is** their bytes, so the same weights at three paths are one component with three occurrences.

Confidence is never hand-waved: per-detector sightings are capped (twelve hits of one regex ≈ one hit, slightly reinforced — repetition can't launder into certainty), independent detection methods corroborate via noisy-OR, and everything clamps at 0.99. Only a content-hash match against known weights may assert 1.0.

## How it works

```
source (fs / repo / image / k8s)
  → Phase 1 — streaming scan: one bounded pipeline; each file read at most once;
    a compiled selector index picks interested detectors; the rule engine runs
    Aho–Corasick keyword prefilters over lexed code/string regions before any regex
  → Phase 2 — project detectors: cross-file logic (HF model dirs, adapter lineage,
    config⇄model binding, RAG stitching) over an immutable phase-1 view
  → Assembler: canonical identity, keep-and-relate merge, confidence calculus,
    parameter binding — detectors emit claims, never components
  → Writers: pure functions from one graph to every output format.
```

The properties that make it production-grade are invariants, not aspirations: peak memory is a function of configuration, never input size; a corrupt file degrades to an honest `Unknown` record instead of killing the scan; identical inputs produce byte-identical output at any parallelism; a 40 GB GGUF inside a container image costs a 32 KB header parse and a hashing pass — zero memory growth, zero disk. Each of these gets a dedicated CI enforcement test as the test matrix lands (Phase 8).

The full design — domain model, detector framework, concurrency topology, identity and confidence calculus, caching, and the decision log with rejected alternatives — is in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Extending AIROM

The detection surface that moves fast — model IDs churn weekly — lives in **declarative YAML rule packs**, not Go. Adding a provider is a rules PR, never a release, and the target is **under one hour**:

1. `airom dev new-rulepack fireworks` scaffolds `rules/models/fireworks.yaml` plus fixture stubs.
2. Write ~30 lines of YAML: keywords (mandatory — they gate an Aho–Corasick prefilter, so your regex only ever runs on files that could match), a pattern or two, a claim template. Add a positive and a negative fixture.
3. `airom rules lint && go test ./rules/... -update` writes the golden output.
4. Your PR is one YAML file, two fixtures, one golden. Zero Go, zero core changes. Review is "do the goldens look right."

Rules can even declare relationships and capture generation parameters at the call site — edges from YAML, no code. For detections that need a real parser (binary headers, cross-file assembly), the Go path is nearly as short: implement `FileDetector` against the stdlib-only `pkg/airom/detect` SDK and validate it with the public `detectortest` harness — the same one the built-in detectors use.

- **[docs/plugin-guide.md](docs/plugin-guide.md)** — both contribution paths, with real diffs
- **[docs/rule-schema.md](docs/rule-schema.md)** — the rule-pack YAML reference

## Project status

AIROM is at **v0.1.0**, its first tagged release: feature-complete against the 10-phase plan, architecture through a multi-agent production review. Early software — expect rough edges, and see the deferred row below for what it deliberately does not do yet. Honest ledger:

| Area | Status |
|---|---|
| Architecture, domain model, decision log ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) | **Complete** — accepted v1 baseline |
| Repository scaffolding on the §4 layout (packages and their contracts, build files, docs) | **Complete** — Phase 2 |
| CLI ([docs/cli.md](docs/cli.md)): scan/fs/repo/image/k8s/clean/version, config layering (flags > env > file > defaults), exit-code contract, `--fail-on` grammar, pprof/trace bootstrap | **Complete** — Phase 3, plus grouped/styled help and a live scan progress indicator that degrades to nothing off a terminal |
| Filesystem scanner: dir source (nested `.gitignore`/`.airomignore` stack, default skips, symlink safety), classification (language/binary/magic), read-once tee-hashed file context, phase-1 streaming pipeline (bounded channels, clamped I/O budget, panic isolation, deterministic output) | **Complete** — Phase 4 |
| Plugin framework: public SDK (`pkg/airom` domain graph with tri-state fields, `pkg/airom/detect` contracts + dispatch index, `purl` discipline, `detectortest` harness), dispatcher with per-detector isolation and accounting, explicit catalog + Syft-style `--select`, assembler (CanonicalKey identity, keep-and-relate merge, grouped noisy-OR confidence, refusal-first relations), rule-engine compiler (full [rule-schema.md](docs/rule-schema.md) lint contract, three-layer merge, self-invalidating ruleset hash, Aho–Corasick prefilter, region lexers for all 8 languages), `detectors-gen`, `airom detectors list/explain` | **Complete** — Phase 5. `airom fs . --rules pack.yaml` runs user rule packs end-to-end today |
| Detectors & rule packs: binary model-file parsers (GGUF, safetensors, ONNX, Torch + static pickle-opcode security scan, SavedModel, TFLite, HDF5, TensorRT — fuzzed), 8-ecosystem manifest detectors, Go AST detector, prompt/dataset/infra detectors, phase-2 project detectors (HF-dir assembly, adapter lineage, config binding, RAG synthesis), 47 embedded rule packs / 98 rules across all 8 categories, `rules list/lint/test` + `dev` scaffolding | **Complete** — Phase 6. Scans a real AI project into a rich AIBOM (models, embeddings, vector DBs, frameworks, weights, prompts, infra, RAG pipelines) |
| Sources: `repo` (exec-git shallow clone + local worktrees), `image` (docker-save/OCI archive + OCI layout — live registry/daemon pull is a follow-up), `k8s` (offline `--manifests` image enumeration — live cluster is a follow-up) | **Complete** — Phase 6 (with the noted follow-ups) |
| Writers: native JSON (versioned, lossless superset — round-trip tested), CycloneDX 1.6/1.7 ML-BOM (modelCard + `evidence.occurrences[]`, validated against the official schemas), SARIF 2.1.0 (one rule per detector, one result per occurrence, line-free fingerprints), YAML, table; multi-output `-o fmt=path` | **Complete** — Phase 7. `airom scan . -o cyclonedx=bom.json -o sarif=scan.sarif` emits both from one pass |
| Test suite: golden end-to-end fixture repos through the whole pipeline into all five formats, official CycloneDX/SARIF schema conformance, `docs/mapping.md` round-trip enforcement, full-scan determinism (`--parallel 1` vs `16`), chaos degradation, and a P2 RSS-ceiling regression harness — everything under `-race`, ~74% coverage | **Complete** — Phase 8 |
| Release automation: CI (lint/vet/gofmt, `-race` tests on Linux+macOS, `CGO_ENABLED=0` cross-compile matrix for all six targets, generated-code drift check, fuzz smoke, CodeQL), goreleaser (static matrix builds, checksums, keyless cosign signing, per-release SBOM + self-scanned AIBOM), Dependabot, issue/PR templates, `SECURITY.md`/`CODE_OF_CONDUCT.md`/`CONTRIBUTING.md` | **Complete** — Phase 9 |
| Production hardening: whole-tree adversarial review (10 dimensions, per-finding verification) that found and fixed 17 verified defects — an OCI-layout path-traversal escape, a static-pickle scan evasion via memo/GET, the unwired `--fail-on` CI gate, a P7 stack-trace leak, YAML int64 corruption, non-canonical purls, and detector/rule-prefilter gaps — each with a regression test. Confirmed the empty CycloneDX `dependencies[]` (no substantiated `depends-on` edges) and the deferred live registry/daemon/cluster modes (fail cleanly) are deliberate, not defects | **Complete** — Phase 10 |
| SPDX 3.0.1 AI profile, attestation verification, per-layer attribution, OCI rule registry, live-cluster/registry source modes, root→dependency edge synthesis | Deferred to v2 by design (reserved slots — see [ARCHITECTURE §16](docs/ARCHITECTURE.md)) |

Known gaps, each surfaced in the affected flag's own `--help` rather than only here: caching is not implemented (every scan is cold, `--no-cache` is a no-op), live registry/daemon image pulls are not available (use `airom image --input <archive>`), and live-cluster scanning is not available (use `airom k8s --manifests <dir>`).

## Comparison

No FUD, just positioning — the tools below solve different problems:

| | AIROM | Registry-centric AIBOM generators | Proprietary AI security scanners |
|---|---|---|---|
| Input | **Your repo, image, or cluster** | A registry entry you name (e.g. an HF repo) | Varies; often model artifacts or SaaS-connected repos |
| Answers "why is this in my AIBOM?" | **Yes — file:line occurrences, technique, confidence in the BOM** | No — output describes the model, not your usage of it | Typically findings without BOM-native evidence |
| CycloneDX `evidence.occurrences[]` | **Emitted** | Not emitted | Not emitted |
| Coverage | Hosted APIs **and** local weights **and** frameworks, vector DBs, prompts, datasets, params, infra, RAG graphs | The named model | Usually model files and/or a curated subset |
| Distribution | Single static Go binary, offline-capable | Python package | Agent or SaaS |
| License | Apache 2.0 | Varies (often open source) | Proprietary |

If you already know exactly which registry model you use and want its card, a registry-centric generator is the right tool. AIROM is for when the ground truth is your codebase and you have to prove it.

## Security

AIROM is a security tool whose parsers eat untrusted bytes, and is hardened accordingly. The posture below is binding design contract ([ARCHITECTURE §13](docs/ARCHITECTURE.md)); the fuzzing and release machinery that enforce it land with the test and release phases (see [Project status](#project-status)):

- **No model execution, ever.** Weight files are identified by magic bytes and bounded header parsing only — nothing is loaded, deserialized into objects, or run.
- **Pickle opcode scanning.** Torch `.pt`/`.pkl` streams are statically walked for suspicious `GLOBAL` opcodes (`os.system`, `subprocess`, `builtins.eval`, …) without execution; results surface as `PickleRisk` on the component.
- **Fuzzed parsers.** Every binary header parser is fuzzed in CI and must return errors — never panic, never allocate unbounded.
- **No surprise network access.** Filesystem, local-repo, and `image --input` scans touch no network; `--offline` asserts it globally.
- **Supply chain.** Releases are `CGO_ENABLED=0`, reproducibly built, cosign-signed, and ship with an SBOM — and, dogfooded, an AIBOM.

A `SECURITY.md` with reporting instructions lands before the first release; until then, report vulnerabilities privately via a GitHub security advisory on the repository, not a public issue.

## Contributing

Start with [docs/plugin-guide.md](docs/plugin-guide.md) (a `CONTRIBUTING.md` lands before the first release). The fastest way to make AIROM better is a rule pack: one YAML file, two fixtures, one golden — most providers land in under an hour.

## License

Licensed under the [Apache License 2.0](LICENSE). © AIROM contributors
