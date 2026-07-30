# AIROM

**Open-source AI Bill of Materials (AIBOM) scanner.**

AIROM is an open-source scanner that discovers AI assets — including models, prompts, datasets, embeddings, vector databases, and AI frameworks — and generates AI Bills of Materials (AIBOMs). It runs as a single static binary over a filesystem, source repository, container image, or Kubernetes cluster, and puts `file:line` evidence behind every entry.

[![CI](https://github.com/airomhq/airom/actions/workflows/ci.yml/badge.svg)](https://github.com/airomhq/airom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/airomhq/airom?include_prereleases)](https://github.com/airomhq/airom/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/airomhq/airom)](https://goreportcard.com/report/github.com/airomhq/airom)
[![Go Reference](https://pkg.go.dev/badge/github.com/airomhq/airom.svg)](https://pkg.go.dev/github.com/airomhq/airom)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **v0.3.4.** Early but real: the pipeline, detectors, rule packs, and every writer are implemented and tested. Three overlays ride on top of the inventory — an **AI-native risk overlay** ([Risk detection](#risk-detection)), a **[CVE overlay](#cve-overlay)** (OSV.dev, on by default), and a **[model lifecycle overlay](#model-lifecycle-eol)** matching the hosted models you call against a curated, dated, sourced catalog of provider retirement announcements — plus **[compliance framework mapping](#compliance-mapping)**, **[test scope](#test-scope)** so fixtures do not masquerade as production AI, and a **signed rule-update channel**. This release is about **AI that leaves no source behind**: frozen PyInstaller binaries are read properly (v0.3.3's parser did not work on any real one), `.sql` schemas are scanned, and a server-side pgvector install is identified from its PostgreSQL extension control file. See [Project status](#project-status) for the honest ledger of what ships today versus what is deferred.

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
| **Frameworks & SDKs** | LangChain, LlamaIndex, Haystack, DSPy, CrewAI, Agno, AutoGen, Semantic Kernel, Transformers, vLLM, MLflow, Crawl4AI, FastMCP, and the provider SDKs — from manifests *and* usage |
| **Frozen applications** | PyInstaller onefile executables — the CArchive/PYZ module list read directly, so AI compiled into a single binary with no `.py`, `.pyc`, or dist-info on disk is still inventoried |
| **Vector databases** | Chroma, Milvus, Qdrant, Pinecone, Weaviate, FAISS, pgvector, Redis, Elasticsearch, MongoDB Atlas — including SQL schema/DDL (`vector`/`halfvec`/`sparsevec` columns, HNSW and IVFFlat indexes) and a server-side pgvector install read from its PostgreSQL extension control file |
| **Prompts** | Prompt files (txt/md/yaml/jinja), `PromptTemplate`/`ChatPromptTemplate`/`system_prompt` patterns |
| **Datasets** | CSV/JSONL/Parquet/Arrow signatures, `load_dataset()`, Kaggle and HF dataset references |
| **Generation parameters** | temperature, top_p, top_k, max_tokens, seed, stop, reasoning effort, response format — bound to the model at the call site, with provenance |
| **Serving infrastructure** | Ollama, vLLM, TGI, Ray Serve, SageMaker, Vertex AI, Azure ML — including Dockerfile/compose/k8s manifests |
| **RAG pipelines** | Retriever + vector store + embedder + LLM stitched into a synthesized `rag-pipeline` composite with typed, evidenced edges |

**Scan targets:** filesystem · git repository (local or URL) · container image (`--input` tarball or OCI layout today; remote/daemon pull is a follow-up) · Kubernetes workloads (offline `--manifests` today; live-cluster is a follow-up)

**Languages:** Python, JavaScript, TypeScript, Go, Java, Rust, C#, Kotlin

**Output formats:** native AIBOM JSON (versioned schema) · CycloneDX 1.6 ML-BOM (with `vulnerabilities[]` for risks and CVEs, and `definitions`/`declarations` for compliance) · SARIF 2.1.0 · YAML · a Markdown compliance report · table — any combination in one scan. SPDX 3.0.1 AI profile is a reserved v2 slot.

## Risk detection

Beyond inventory, AIROM flags **AI-native security risks** — load-time code-execution and injection surfaces that a generic SBOM or secret scanner never looks for. Each risk attaches to the component it concerns, carries `file:line` evidence, and is treated as **suspicion with evidence, never a verdict**: a static scan is evadable by construction, so the absence of a risk is not a safety claim.

| Risk | Severity | What it catches |
|---|---|---|
| `pickle-import` | high | A Torch checkpoint whose pickle resolves a code-execution callable (`os.system`, `subprocess`, `builtins.eval`, …) |
| `keras-lambda` | high | A Keras HDF5 config declaring a `Lambda` layer — marshalled Python that runs at `load_model` |
| `gguf-template` | medium | A GGUF `chat_template` carrying Jinja sandbox-escape gadgets (`__globals__`, `os.popen`, …) |
| `savedmodel-pyfunc` | medium | A TensorFlow SavedModel graph invoking a `PyFunc`-family Python callback |
| `unsafe-load` | medium | A `torch.load(..., weights_only=False)` call site — an explicit opt-out of safe deserialization |

Risks project natively into **CycloneDX `vulnerabilities[]`** (non-CVE ids with a named source; no fabricated CVSS), **SARIF security results** carrying GitHub's `security-severity` — so a poisoned checkpoint becomes a Code Scanning alert on the PR that introduced it — the native JSON/YAML, and the CI gate:

```bash
airom scan . --exit-code 1 --fail-on "risk:high"          # fail on any high-severity risk
airom scan . --exit-code 1 --fail-on "risk:unsafe-load"   # or one specific risk
```

It stays deterministic and offline — no LLM, no vulnerability database. And it extends without Go: any rule pack can attach a catalog risk to a match via a `risk:` field. The full catalog and the model behind it are in **[docs/risks.md](docs/risks.md)**.

## Test scope

An AIBOM answers "what AI does this software use?" — and a rule-pack fixture
calling `model="gpt-4-32k"` is not an answer. AI reached **only** from test
scaffolding (`testdata/`, `*_test.go`, `tests/`, `spec/`, `test_*.py`,
`*.spec.ts`, …) is recorded but kept out of the default view.

This is not a cosmetic trim. Scanning AIROM's own repository produces 185
components, **180 of them fixtures** — without scoping, the document reads as if
a Go scanner that calls no models depended on fifty hosted LLMs.

Nothing is dropped. What changes is which surface counts it:

| Surface | Test-scoped components |
|---|---|
| Native JSON / YAML | present, `"testOnly": true` |
| CycloneDX | present, `"scope": "excluded"` — the standard's own field for "not in the deployed artifact" |
| Table | hidden, with a count of what was withheld |
| SARIF | omitted (an alert on a fixture is a notification someone must dismiss) |
| `--fail-on` | not counted (a gate that fails over a file shipping to nobody gets deleted) |
| Compliance mapping | not counted as evidence, nor as a gap |

Paths are matched **relative to the scan root**, so pointing AIROM at a fixture
directory reports it normally. Matching is exact and conventional, never a
substring — `src/testimonials.py` and `models/latest/` are production code. And
the rule is *all*, not *any*: a model reached from production code stays in the
report even when tests reach it too.

```bash
airom fs . --include-tests    # when the question is "what do our tests reach for?"
```

## AIBOM diff

A scan answers *"what AI is in this repo?"* — a snapshot. The question security teams live with is **"what AI changed?"** `airom diff` compares two native AIBOM documents and reports the semantic delta: components added, removed, and changed, keyed by the stable component ID. Version is not part of identity, so a version bump reads as a field change on one component, never as a remove+add pair — and evidence churn is not compared, so two scans of unchanged code diff as empty.

```bash
airom scan . -o json=head.json && airom diff base.json head.json   # what changed?
airom diff base.json head.json --format markdown                   # ready to post as a PR comment
airom diff base.json head.json --fail-on "hosted-llm|local-model-file"   # no new AI providers without sign-off
airom diff base.json head.json --exit-code 1                       # any AI change fails the build
```

This turns AIROM from a point-in-time inventory into a **per-PR control**: scan the base branch and the head, diff the two, post the markdown to the PR, and gate the merge on the delta you refuse to accept — a new hosted model, new local weights, a new vector store, a component that just picked up a `pickle-import` risk. Removals never trip the gate. Added and removed components carry their **RISK**, **VULN**, and **EOL** columns when the delta surfaces one, so a PR that introduces a retired model or a checkpoint that executes code on load says so in the row. And because a diff attributes its delta to the code, `airom diff` compares the two documents' tooling provenance — binary, ruleset, lifecycle catalog — and refuses to gate across a mismatch rather than blame a PR for a rule change. Three formats — `table`, `markdown`, `json` — all projections of the same result; details in **[docs/cli.md](docs/cli.md)**.

## Model lifecycle (EOL)

The risk and CVE overlays answer questions about *risk*. This one answers a question about *time*: **what in this stack stops working, and when?** A retired hosted model is not a vulnerability you weigh — on the shutdown date the provider's API stops answering and the app breaks, patched or not.

```bash
airom scan .                                            # lifecycle shown by default
airom scan . --exit-code 1 --fail-on "eol:retired"      # block on a model already gone
airom scan . --exit-code 1 --fail-on "eol:before:2027-01-01"  # dies before the next release train
```

```
Model lifecycle (3)
┌──────────────────────────┬───────────┬────────────┬────────────┬──────┬─────────────────┐
│ MODEL                    │ PROVIDER  │ STATE      │ SHUTDOWN   │ DAYS │ MIGRATE TO      │
├──────────────────────────┼───────────┼────────────┼────────────┼──────┼─────────────────┤
│ gpt-4-32k                │ openai    │ RETIRED    │ 2025-06-06 │ -417 │ gpt-4o          │
│ claude-opus-4-1-20250805 │ anthropic │ DEPRECATED │ 2026-08-05 │ 8    │ claude-opus-4-8 │
│ gpt-4-turbo              │ openai    │ DEPRECATED │ 2026-10-23 │ 87   │ gpt-5.6-sol     │
└──────────────────────────┴───────────┴────────────┴────────────┴──────┴─────────────────┘
```

**On by default and fully offline** — the curated catalog ships in the binary, so an airgapped scan still answers it (`--no-eol` opts out). Every record is **transcribed from the provider's own deprecation page** with that URL and a verification date; nothing is inferred from naming. A model the catalog doesn't cover reports `unknown` — *no claim*, never a quiet "supported". Migration advice carries the target's own state, because providers routinely point a deprecation at a model since deprecated itself. It projects as CycloneDX component properties and SARIF results — **not** `vulnerabilities[]`, since a scheduled vendor shutdown is an availability fact no patch fixes. Full contract in **[docs/eol.md](docs/eol.md)**.

## Compliance mapping

`--compliance <framework>` maps the AIBOM onto an AI-governance framework's controls and decides **met / gap / manual** for each — with the `file:line` evidence behind every verdict.

```bash
airom scan . --compliance nist-ai-rmf -o compliance=report.md -o cyclonedx=bom.json
```

It's a **mapping, never a certification.** Most of these frameworks are organizational *process* a static scan can't verify; those controls are marked `manual` and carry **no score** — AIROM never asserts conformance it can't back. An `evidence_of` "met" points at the concrete components that satisfy it. Frameworks today: **`nist-ai-rmf`** (NIST AI RMF 1.0) and **`owasp-agentic`** (OWASP Agentic AI — mostly manual, honestly, since agentic threats are runtime; its RCE threat maps to the risk overlay).

It projects into CycloneDX's **native attestation model** — `definitions.standards[]` (the framework + its requirements) and `declarations` (AIROM as a first-party assessor; a claim + graded `conformance.score` per control) — plus a Markdown report (`-o compliance`) and a CI gate:

```bash
airom scan . --compliance nist-ai-rmf --exit-code 1 --fail-on "compliance:gap"
```

That evidence-linked conformance is something a tool that drops evidence on export structurally cannot produce. Details and the honest-mapping contract are in **[docs/compliance.md](docs/compliance.md)**.

## CVE overlay

The core scan is offline and deterministic — it reports what an artifact *is*. The CVE overlay adds what is *known about it today*: it matches the AI package dependencies AIROM inventoried (by their purl) against the live **[OSV.dev](https://osv.dev)** database and attaches the resulting CVEs — with real CVSS v3 scores computed from each vector — to those components. It's **on by default**.

```bash
airom scan .                                    # CVEs included in every output format
airom scan . --exit-code 1 --fail-on "cve:high" # fail CI on a high/critical CVE
airom scan . --no-cve                           # skip it — offline, byte-stable BOM
```

Disable it with `--no-cve` (or `--offline`) when you want an offline, reproducible BOM — it touches the network and isn't deterministic across time (the same scan surfaces more CVEs as OSV grows). It's **scoped to AI dependencies**, not a general-purpose SCA, and it **degrades honestly** — a network failure yields no CVEs and a warning, never a failed scan (except an active `--fail-on cve` gate fails closed rather than silently pass). CVEs project into CycloneDX `vulnerabilities[]` (with a genuine `CVSSv31` rating), SARIF `cve/<id>` security results carrying the real base score, a `VULN` column plus a per-CVE detail table, and the `cve` / `cve:<severity>` gate. Full contract in **[docs/cve.md](docs/cve.md)**.

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

AI Bill of Materials — /tmp/my-rag-app

┌─ Scan Summary ────────────────┐
│ Target        /tmp/my-rag-app │
│ Components    8               │
│ Files         5 scanned       │
│                               │
│ By Type                       │
│   library            2        │
│   embedding-model    1        │
│   framework          1        │
│   hosted-llm         1        │
│   local-model-file   1        │
│   prompt             1        │
│   vector-db          1        │
│                               │
│ Vulnerabilities               │
│   total              3        │
│   critical           1        │
│   high               2        │
└───────────────────────────────┘

┌──────────────────┬───────────────────────────────┬─────────┬─────────────┬───────┬──────────────┬────────────────────┬──────────┐
│ KIND             │ NAME                          │ VERSION │ PROVIDER    │ CONF  │ VULN         │ LOCATION           │ EVIDENCE │
├──────────────────┼───────────────────────────────┼─────────┼─────────────┼───────┼──────────────┼────────────────────┼──────────┤
│ embedding-model  │ openai/text-embedding-3-large │ -       │ openai      │ 0.85  │ -            │ src/rag.py:6       │ 1 occ    │
│ framework        │ langchain/langchain           │ 0.2.16  │ langchain   │ 0.95  │ high (2)     │ requirements.txt:2 │ 1 occ    │
│ hosted-llm       │ openai/gpt-4.1                │ -       │ openai      │ 0.85  │ -            │ src/rag.py:15      │ 1 occ    │
│ library          │ openai                        │ 1.51.0  │ openai      │ 0.985 │ -            │ requirements.txt:3 │ 1 occ    │
│ library          │ transformers                  │ 4.44.0  │ huggingface │ 0.95  │ critical (1) │ requirements.txt:5 │ 1 occ    │
│ local-model-file │ tiny.gguf                     │ -       │ local       │ 0.95  │ -            │ models/tiny.gguf   │ 1 occ    │
│ prompt           │ system.txt                    │ -       │ -           │ 0.8   │ -            │ prompts/system.txt │ 1 occ    │
│ vector-db        │ chroma                        │ 0.5.5   │ chroma      │ 0.985 │ -            │ requirements.txt:4 │ 1 occ    │
└──────────────────┴───────────────────────────────┴─────────┴─────────────┴───────┴──────────────┴────────────────────┴──────────┘

Vulnerabilities (3)
┌─────────────────────┬────────────────┬──────────┬────────┬───────────┬────────┬──────────────────────────────────────────────────┐
│ LIBRARY             │ VULNERABILITY  │ SEVERITY │ STATUS │ INSTALLED │ FIXED  │ TITLE                                            │
├─────────────────────┼────────────────┼──────────┼────────┼───────────┼────────┼──────────────────────────────────────────────────┤
│ transformers        │ CVE-2024-11392 │ CRITICAL │ fixed  │ 4.44.0    │ 4.48.0 │ Deserialization of untrusted data in the Trax    │
│                     │                │          │        │           │        │ model loader.                                    │
│                     │                │          │        │           │        │ https://osv.dev/vulnerability/CVE-2024-11392     │
├─────────────────────┼────────────────┼──────────┼────────┼───────────┼────────┼──────────────────────────────────────────────────┤
│ langchain/langchain │ CVE-2024-46946 │ HIGH     │ fixed  │ 0.2.16    │ 0.3.0  │ SSRF in the LangChain experimental LLMMathChain. │
│                     │                │          │        │           │        │ https://osv.dev/vulnerability/CVE-2024-46946     │
│                     ├────────────────┼──────────┼────────┤           ├────────┼──────────────────────────────────────────────────┤
│                     │ CVE-2024-8309  │ HIGH     │ fixed  │           │ 0.2.19 │ SQL injection via the SQLDatabase chain in       │
│                     │                │          │        │           │        │ LangChain.                                       │
│                     │                │          │        │           │        │ https://osv.dev/vulnerability/CVE-2024-8309      │
└─────────────────────┴────────────────┴──────────┴────────┴───────────┴────────┴──────────────────────────────────────────────────┘
```

> The **CVE overlay runs by default**: the `VULN` column flags affected components, the summary counts CVEs by severity, and the per-CVE detail table lists each advisory (most-severe first) with its fix and title. Per-package columns (`LIBRARY`, `INSTALLED`, `FIXED`) merge across a package's CVEs, Trivy-style — note `langchain`'s two rows share one library/installed cell. Pass `--no-cve` (or `--offline`) to skip it for a byte-stable, offline BOM. `LOCATION` is each component's primary `file:line`; `--wide` lists every occurrence. Load-time **risks** (pickle, Lambda, …) still surface in the CycloneDX/SARIF/JSON outputs — see [Risk detection](#risk-detection).

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

AIROM is at **v0.3.4**: feature-complete against the 10-phase plan, architecture through a multi-agent production review, with three overlays (artifact risk, CVE, model lifecycle), compliance mapping, test-scope filtering, per-PR AIBOM diffing, lockfile and installed-metadata version resolution, and a signed rule-update channel — now checked automatically, once a day, outside CI — added on top. Early software — expect rough edges, and see the deferred row below for what it deliberately does not do yet. Honest ledger:

| Area | Status |
|---|---|
| Architecture, domain model, decision log ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) | **Complete** — accepted v1 baseline |
| Repository scaffolding on the §4 layout (packages and their contracts, build files, docs) | **Complete** — Phase 2 |
| CLI ([docs/cli.md](docs/cli.md)): scan/fs/repo/image/k8s/clean/version, config layering (flags > env > file > defaults), exit-code contract, `--fail-on` grammar, pprof/trace bootstrap | **Complete** — Phase 3, plus grouped/styled help and a live scan progress indicator that degrades to nothing off a terminal |
| Filesystem scanner: dir source (nested `.gitignore`/`.airomignore` stack, default skips, symlink safety), classification (language/binary/magic), read-once tee-hashed file context, phase-1 streaming pipeline (bounded channels, clamped I/O budget, panic isolation, deterministic output) | **Complete** — Phase 4 |
| Plugin framework: public SDK (`pkg/airom` domain graph with tri-state fields, `pkg/airom/detect` contracts + dispatch index, `purl` discipline, `detectortest` harness), dispatcher with per-detector isolation and accounting, explicit catalog + Syft-style `--select`, assembler (CanonicalKey identity, keep-and-relate merge, grouped noisy-OR confidence, refusal-first relations), rule-engine compiler (full [rule-schema.md](docs/rule-schema.md) lint contract, three-layer merge, self-invalidating ruleset hash, Aho–Corasick prefilter, region lexers for all 8 languages), `detectors-gen`, `airom detectors list/explain` | **Complete** — Phase 5. `airom fs . --rules pack.yaml` runs user rule packs end-to-end today |
| Detectors & rule packs: binary model-file parsers (GGUF, safetensors, ONNX, Torch, SavedModel, TFLite, HDF5, TensorRT — fuzzed) with an artifact-risk overlay (pickle imports, Keras Lambda, GGUF template gadgets, SavedModel PyFunc → CycloneDX `vulnerabilities[]`/SARIF), 8-ecosystem manifest detectors plus lockfile (npm/yarn/pnpm/poetry/uv/pipenv) and installed-metadata (`.dist-info`/`.egg-info`) version resolution, Go AST detector, prompt/dataset/infra detectors, phase-2 project detectors (HF-dir assembly, adapter lineage, config binding, RAG synthesis), 49 embedded rule packs / 102 rules across 9 categories (incl. a `security` category and a rule-level `risk:` field), `rules list/lint/test` + `dev` scaffolding | **Complete** — Phase 6. Scans a real AI project into a rich AIBOM (models, embeddings, vector DBs, frameworks, weights, prompts, infra, RAG pipelines) |
| Sources: `repo` (exec-git shallow clone + local worktrees), `image` (docker-save/OCI archive + OCI layout — live registry/daemon pull is a follow-up), `k8s` (offline `--manifests` image enumeration — live cluster is a follow-up) | **Complete** — Phase 6 (with the noted follow-ups) |
| Writers: native JSON (versioned, lossless superset — round-trip tested), CycloneDX 1.6/1.7 ML-BOM (modelCard + `evidence.occurrences[]` + `vulnerabilities[]` for risks + `definitions`/`declarations` for compliance, validated against the official schemas), SARIF 2.1.0 (one rule per detector/risk, one result per occurrence, line-free fingerprints), YAML, a Markdown compliance report, table; multi-output `-o fmt=path` | **Complete** — Phase 7. `airom scan . -o cyclonedx=bom.json -o sarif=scan.sarif` emits both from one pass |
| Compliance mapping (`--compliance`): AIBOM → governance-framework controls (met/gap/manual, no fabricated scores), projected as CycloneDX attestations + a Markdown report, gateable via `--fail-on compliance:gap`. Frameworks: NIST AI RMF 1.0, OWASP Agentic AI ([docs/compliance.md](docs/compliance.md)) | **Complete** — evidence-linked, deterministic, offline |
| CVE overlay (on by default, `--no-cve`): the AI packages AIROM inventoried, queried against OSV.dev, into CycloneDX `vulnerabilities[]` / SARIF / a Trivy-style detail table, with a locally computed CVSS score, a version-aware fixed-in, and a fail-closed `--fail-on cve` gate ([docs/cve.md](docs/cve.md)) | **Complete** — the only overlay that needs the network; refuses under `--offline` rather than reporting a quiet nothing |
| Model lifecycle / EOL overlay (on by default, `--no-eol`): hosted models matched against a curated catalog of provider retirement announcements — every claim dated and sourced, none inferred from naming, gateable via `--fail-on eol` ([docs/eol.md](docs/eol.md)) | **Complete** — offline; a model the catalog does not cover carries **no claim**, never a quiet "supported" |
| AIBOM diff (`airom diff <old> <new>`): the semantic delta between two native documents — added / removed / changed, keyed by stable component ID, with the risk, CVE, and lifecycle overlays on the rows. `table`/`markdown`/`json`, gateable via `--fail-on` over added and changed only ([docs/cli.md](docs/cli.md)) | **Complete** — refuses to gate when the two documents came from different tooling, rather than blaming a PR for a rule change |
| Signed rule-update channel (`airom rules update`): ed25519-verified bundles from [airomhq/airom-rules](https://github.com/airomhq/airom-rules) carrying rule packs and lifecycle catalogs, so detection and retirement dates refresh without a new binary; every AIBOM records `rulesVersion` + `rulesHash` + `eolCatalog` ([docs/cli.md](docs/cli.md)) | **Complete** — the only network path outside `--cve`; scans themselves never fetch |
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
| Load-time risk detection | **Built in — pickle / Lambda / template / PyFunc / unsafe-load, as CycloneDX `vulnerabilities[]` + SARIF, offline** | No | Varies — some scan model artifacts, typically SaaS or agent-based |
| Known-CVE overlay | **On by default — AI deps matched against OSV.dev with real CVSS v3 scores, into the same `vulnerabilities[]`/SARIF; `--no-cve` for offline/reproducible** | Rarely | Sometimes, usually as the core product |
| Compliance mapping | **Evidence-linked — NIST AI RMF / OWASP Agentic as CycloneDX attestations, honest about what a scan can't verify** | No | Sometimes, but without BOM-native evidence |
| Coverage | Hosted APIs **and** local weights **and** frameworks, vector DBs, prompts, datasets, params, infra, RAG graphs | The named model | Usually model files and/or a curated subset |
| Distribution | Single static Go binary, offline-capable | Python package | Agent or SaaS |
| License | Apache 2.0 | Varies (often open source) | Proprietary |

If you already know exactly which registry model you use and want its card, a registry-centric generator is the right tool. AIROM is for when the ground truth is your codebase and you have to prove it.

## Security

AIROM is a security tool whose parsers eat untrusted bytes, and is hardened accordingly. The posture below is binding design contract ([ARCHITECTURE §13](docs/ARCHITECTURE.md)); the fuzzing and release machinery that enforce it land with the test and release phases (see [Project status](#project-status)):

- **No model execution, ever.** Weight files are identified by magic bytes and bounded header parsing only — nothing is loaded, deserialized into objects, or run.
- **Static artifact-risk scanning.** Model files and load-time code are walked for execution/injection surfaces — pickle imports, Keras Lambda layers, GGUF template gadgets, SavedModel Python callbacks, unsafe `torch.load` — without ever executing them. Findings surface as an evidence-linked risk overlay (CycloneDX `vulnerabilities[]`, SARIF, `--fail-on risk`); see [Risk detection](#risk-detection) and [docs/risks.md](docs/risks.md).
- **Fuzzed parsers.** Every binary header parser is fuzzed in CI and must return errors — never panic, never allocate unbounded.
- **No surprise network access.** Filesystem, local-repo, and `image --input` scans touch no network; `--offline` asserts it globally.
- **Supply chain.** Releases are `CGO_ENABLED=0`, reproducibly built, cosign-signed, and ship with an SBOM — and, dogfooded, an AIBOM.

Report vulnerabilities privately via a GitHub security advisory on the repository, not a public issue — see [SECURITY.md](SECURITY.md).

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/plugin-guide.md](docs/plugin-guide.md). The fastest way to make AIROM better is a rule pack: one YAML file, two fixtures, one golden — most providers land in under an hour.

## License

Licensed under the [Apache License 2.0](LICENSE). © AIROM contributors
