# AIROM

**AIROM is to AI systems what Trivy is to SBOMs** — a single static binary that discovers every AI asset in a filesystem, source repository, container image, or Kubernetes cluster and emits an AI Bill of Materials (AIBOM) with file:line evidence behind every entry.

[![CI](https://github.com/Roro1727/airom/actions/workflows/ci.yml/badge.svg)](https://github.com/Roro1727/airom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Roro1727/airom?include_prereleases)](https://github.com/Roro1727/airom/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/Roro1727/airom)](https://goreportcard.com/report/github.com/Roro1727/airom)
[![Go Reference](https://pkg.go.dev/badge/github.com/Roro1727/airom.svg)](https://pkg.go.dev/github.com/Roro1727/airom)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Pre-release.** AIROM is under active development (v0.1.0-dev, unpublished). The design below is fixed; see [Project status](#project-status) for what is implemented today versus in flight.

---

## What is AIROM?

Sooner or later, an auditor, a customer, or your own security team asks the question:

> *"Your AIBOM says this service uses `gpt-4.1`. **Why?** Where, exactly?"*

Most AIBOM tools can't answer it. They are registry-centric — you name a model on Hugging Face, they render a model card — or they are proprietary and never look at your code at all. Nobody scans *the repository you actually ship* and shows their work.

AIROM is **evidence-first**. Every component in the output carries:

- **Occurrences** — `file:line`, matched snippet, and enclosing symbol for every sighting
- **Detection technique** — source-code analysis, binary header parse, manifest analysis, hash comparison, …
- **A calibrated confidence score** — with the arithmetic behind it, not a vibe

That evidence is emitted as CycloneDX 1.6 `evidence.identity[]` + `evidence.occurrences[]` — a spec-native home for "seen at file:line, by technique T, with confidence C" that **no other shipping AIBOM tool populates** — plus a SARIF projection so the same findings land as annotations in GitHub Code Scanning. One scan, one graph, every format a pure projection of it.

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

**Scan targets:** filesystem · git repository (local or URL) · container image (remote, daemon, tarball, OCI layout) · Kubernetes workloads (live cluster or offline manifests)

**Languages:** Python, JavaScript, TypeScript, Go, Java, Rust, C#, Kotlin

**Output formats:** native AIBOM JSON (versioned schema) · CycloneDX 1.6 ML-BOM · SARIF 2.1.0 · YAML · table — any combination in one scan. SPDX 3.0.1 AI profile is a reserved v2 slot.

## Quick start

### Install

```bash
# Go (available once v0.1.0 is published)
go install github.com/Roro1727/airom/cmd/airom@latest
```

Prebuilt, cosign-signed binaries will ship on the [releases page](https://github.com/Roro1727/airom/releases) with each release; a Homebrew tap is planned. AIROM releases as a single static binary (`CGO_ENABLED=0`) — no runtime, no dependencies.

### Scan

```bash
# Auto-detect the target: directory, git URL, or image reference
airom scan .

# Explicit nouns, Trivy-style
airom fs ./my-service
airom repo https://github.com/org/rag-app
airom image nginx:latest
airom k8s --namespace ml-serving

# Multiple outputs from one scan: table to the terminal,
# CycloneDX and SARIF to files
airom scan . -o table -o cyclonedx=bom.json -o sarif=scan.sarif

# Narrow the detector set; add your own rules
airom scan . --select "python,+modelfile/gguf,-dataset" --rules extra.yaml
```

**Exit codes:** `airom` exits **0 when the scan succeeds — findings are not failures**. Gating is opt-in CI policy:

```bash
airom scan . --exit-code 1 --fail-on "local-model-file&confidence>=0.9"
```

## Example output

```
$ airom scan .

AIROM v0.1.0  ·  fs:.  ·  1,284 files walked, 212 read, 38ms

KIND              NAME                         VERSION   PROVIDER   CONF   EVIDENCE   FIRST SEEN
hosted-llm        gpt-4.1                      -         openai     0.87   12         src/rag.py:88
embedding-model   text-embedding-3-large       -         openai     0.85   3          src/embed.py:17
local-model-file  llama-3-8b-instruct.Q4_K_M   -         local      0.97   2          models/llama-3-8b.gguf
framework         langchain                    0.3.14    -          0.95   2          requirements.txt:12
vector-db         chromadb                     0.6.3     -          0.92   4          requirements.txt:18
prompt            system-prompt.md             -         local      0.80   1          prompts/system-prompt.md
rag-pipeline      rag-pipeline#1               -         -          0.78   -          (synthesized)
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
  → Writers: pure functions from one graph to every output format
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

AIROM is **pre-release (v0.1.0-dev)**, building out in phases toward a first tagged release. Phase 1 of the 10-phase plan — the architecture — is accepted and stable; implementation lands phase by phase, and Phase 2 (repository structure) is current. Honest ledger:

| Area | Status |
|---|---|
| Architecture, domain model, decision log ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) | **Complete** — accepted v1 baseline |
| Repository scaffolding on the §4 layout (packages and their contracts, build files, docs) | **Complete** — Phase 2 |
| CLI ([docs/cli.md](docs/cli.md)): scan/fs/repo/image/k8s/clean/version, config layering (flags > env > file > defaults), exit-code contract, `--fail-on` grammar, pprof/trace bootstrap | **Complete** — Phase 3. Scan commands fail fast with a clear error until the engine lands (Phase 4); `detectors`/`rules`/`dev` command groups arrive with their subsystems (Phases 5–6) |
| Filesystem scanner: dir source (nested `.gitignore`/`.airomignore` stack, default skips, symlink safety), classification (language/binary/magic), read-once tee-hashed file context, phase-1 streaming pipeline (bounded channels, clamped I/O budget, panic isolation, deterministic output) | **Complete** — Phase 4 |
| Plugin framework: public SDK (`pkg/airom` domain graph with tri-state fields, `pkg/airom/detect` contracts + dispatch index, `purl` discipline, `detectortest` harness), dispatcher with per-detector isolation and accounting, explicit catalog + Syft-style `--select`, assembler (CanonicalKey identity, keep-and-relate merge, grouped noisy-OR confidence, refusal-first relations), rule-engine compiler (full [rule-schema.md](docs/rule-schema.md) lint contract, three-layer merge, self-invalidating ruleset hash, Aho–Corasick prefilter, region lexers for all 8 languages), `detectors-gen`, `airom detectors list/explain` | **Complete** — Phase 5. `airom fs . --rules pack.yaml` runs user rule packs end-to-end today |
| Detectors & rule packs: binary model-file parsers (GGUF, safetensors, ONNX, Torch + static pickle-opcode security scan, SavedModel, TFLite, HDF5, TensorRT — fuzzed), 8-ecosystem manifest detectors, Go AST detector, prompt/dataset/infra detectors, phase-2 project detectors (HF-dir assembly, adapter lineage, config binding, RAG synthesis), 47 embedded rule packs / 98 rules across all 8 categories, `rules list/lint/test` + `dev` scaffolding | **Complete** — Phase 6. Scans a real AI project into a rich AIBOM (models, embeddings, vector DBs, frameworks, weights, prompts, infra, RAG pipelines) |
| Sources: `repo` (exec-git shallow clone + local worktrees), `image` (docker-save/OCI archive + OCI layout — live registry/daemon pull is a follow-up), `k8s` (offline `--manifests` image enumeration — live cluster is a follow-up) | **Complete** — Phase 6 (with the noted follow-ups) |
| Binary model-file parsers (GGUF, safetensors, ONNX, torch/pickle, …) | Designed, lands with the detector phases |
| Writers: native JSON, CycloneDX 1.6, SARIF, YAML, table | Designed, lands with the output phases |
| Image & k8s sources, caching, phase-2 project detectors, RAG stitching | Designed, later phases |
| SPDX 3.0.1 AI profile, attestation verification, per-layer attribution, OCI rule registry | Deferred to v2 by design (reserved slots — see [ARCHITECTURE §16](docs/ARCHITECTURE.md)) |

Until v0.1.0 is tagged, the badges above may 404 and `go install` will not resolve — the module is unpublished.

## Comparison

No FUD, just positioning — the tools below solve different problems:

| | AIROM | Registry-centric AIBOM generators | Proprietary AI security scanners |
|---|---|---|---|
| Input | **Your repo, image, or cluster** | A registry entry you name (e.g. an HF repo) | Varies; often model artifacts or SaaS-connected repos |
| Answers "why is this in my AIBOM?" | **Yes — file:line occurrences, technique, confidence in the BOM** | No — output describes the model, not your usage of it | Typically findings without BOM-native evidence |
| CycloneDX `evidence.occurrences[]` | **Emitted** | Not emitted | Not emitted |
| Coverage | Hosted APIs **and** local weights **and** frameworks, vector DBs, prompts, datasets, params, infra, RAG graphs | The named model | Usually model files and/or a curated subset |
| Distribution | Single static Go binary, offline-capable | Python package | Agent or SaaS |
| License | MIT | Varies (often open source) | Proprietary |

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

[MIT](LICENSE) © AIROM contributors
