# AIROM

**The AI bill of materials that shows its work.**

AIROM scans a filesystem, git repo, container image, or Kubernetes workload and
generates an **AI Bill of Materials**: the models, prompts, datasets, embeddings,
vector databases, and frameworks your software actually uses. Every entry carries
`file:line` evidence.

[![CI](https://github.com/airomhq/airom/actions/workflows/ci.yml/badge.svg)](https://github.com/airomhq/airom/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/airomhq/airom?include_prereleases)](https://github.com/airomhq/airom/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/airomhq/airom)](https://goreportcard.com/report/github.com/airomhq/airom)
[![Go Reference](https://pkg.go.dev/badge/github.com/airomhq/airom.svg)](https://pkg.go.dev/github.com/airomhq/airom)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Quick start

```bash
pip install airom
```

```bash
airom scan .
```

That's it. One static binary, no runtime, no daemon, no account.

```
┌──────────────────┬────────────────────────┬─────────┬─────────────┬───────┬────────────────────┬──────────┐
│ KIND             │ NAME                   │ VERSION │ PROVIDER    │ CONF  │ LOCATION           │ EVIDENCE │
├──────────────────┼────────────────────────┼─────────┼─────────────┼───────┼────────────────────┼──────────┤
│ embedding-model  │ text-embedding-3-large │ -       │ openai      │ 0.85  │ src/rag.py:6       │ 1 occ    │
│ framework        │ langchain              │ 0.2.16  │ langchain   │ 0.95  │ requirements.txt:2 │ 1 occ    │
│ hosted-llm       │ gpt-4.1                │ -       │ openai      │ 0.85  │ src/rag.py:15      │ 1 occ    │
│ library          │ openai                 │ 1.51.0  │ openai      │ 0.985 │ requirements.txt:3 │ 2 occ    │
│ local-model-file │ tiny.gguf              │ -       │ local       │ 0.95  │ models/tiny.gguf   │ 1 occ    │
│ prompt           │ system.txt             │ -       │ -           │ 0.8   │ prompts/system.txt │ 1 occ    │
│ rag-pipeline     │ rag-pipeline           │ -       │ -           │ 0.6   │ src/rag.py:6       │ 1 occ    │
│ vector-db        │ chroma                 │ 0.5.5   │ chroma      │ 0.985 │ requirements.txt:4 │ 3 occ    │
└──────────────────┴────────────────────────┴─────────┴─────────────┴───────┴────────────────────┴──────────┘
```

More ways to install and run: **[installation](https://docs.airom.dev/installation)** ·
**[quickstart](https://docs.airom.dev/quickstart)** · **[CLI reference](docs/cli.md)**

## Common commands

```bash
airom scan .                              # a directory
airom repo https://github.com/org/app     # a git URL
airom image --input app.tar               # a container image archive
airom k8s --manifests ./deploy            # Kubernetes workloads

airom scan . -o cyclonedx=bom.json -o spdx=bom.spdx.json  # many formats, one pass
airom scan . --fix --fix-verify                          # fix the CVEs it found, one click each
airom scan . --exit-code 1 --fail-on "risk:high"         # gate a build
airom diff base.json head.json                           # what a PR changed
```

## What it finds

| | |
|---|---|
| **Hosted models** | OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Cohere, Mistral, Groq. Model IDs and SDK call sites |
| **Local weights** | GGUF, safetensors, ONNX, PyTorch, SavedModel, TFLite, HDF5, TensorRT. Identified by magic bytes and header parse, and **never loaded or run** |
| **Frameworks** | LangChain, LlamaIndex, CrewAI, Agno, AutoGen, Semantic Kernel, CAMEL, MetaGPT, Letta, Crawl4AI, FastMCP, Transformers, and more |
| **Local inference & training** | vLLM, llama.cpp, GPT4All, Ollama, DeepSpeed, Unsloth |
| **Vector databases** | Chroma, Milvus, Qdrant, Pinecone, Weaviate, FAISS, Redis, pgvector. Includes SQL schemas and a server-side pgvector install |
| **Prompts & datasets** | Prompt files and templates, CSV/JSONL/Parquet signatures, `load_dataset()`, HF and Kaggle references |
| **Everything else** | Generation parameters bound to their call site, serving infrastructure, and RAG pipelines stitched into one component |

Dependencies are read from manifests, **lockfiles**, **installed metadata**, and
even **PyInstaller binaries**, so a frozen app with no source on disk still
produces an inventory.

**Languages:** Python · JavaScript · TypeScript · Go · Java · Rust · C# · Kotlin · SQL

## Why AIROM

Sooner or later someone asks: *"Your AIBOM says this service uses `gpt-4.1`.
Why? Where?"*

Most tools can't answer. They describe a model you named in a registry, or they
never look at your code. AIROM is **evidence-first**: every component carries
the `file:line` it was seen at, the technique that found it, and an
evidence-weighted confidence score, emitted as CycloneDX `evidence.occurrences[]` that other
AIBOM tools leave empty.

It is also honest about what it doesn't know. A version it couldn't resolve
stays empty instead of guessing; a model outside the lifecycle catalog carries
no claim rather than a quiet "supported".

## Beyond inventory

| Feature | What it does |
|---|---|
| [Risk detection](docs/risks.md) | Load-time code-execution surfaces: pickle imports, Keras Lambda layers, GGUF template gadgets, and unsafe `torch.load`. Emitted as CycloneDX `vulnerabilities[]` and SARIF. Offline. |
| [CVE overlay](docs/cve.md) | Your AI dependencies against OSV.dev, with real CVSS scores and a fail-closed gate. On by default. |
| [One-click fixes](docs/cve.md#fixing-what-it-finds) | `--fix` opens the advisory table with a **Fix** action per package and rewrites the manifest pin you click. Declared manifests only — a lockfile is reported, never forged. `--fix-verify` then dry-runs the ecosystem's resolver, so a bump that clears eight CVEs and leaves a manifest nothing can install is caught here, not in your next build. |
| [Model lifecycle](docs/eol.md) | Hosted models matched against a dated, sourced catalog of provider retirement announcements. |
| [Compliance mapping](docs/compliance.md) | NIST AI RMF and OWASP Agentic controls as CycloneDX attestations, marked met, gap, or manual, with no invented scores. |
| [VEX export](docs/cli.md) | An OpenVEX document over the CVE overlay, for consumers that ingest VEX. Only ever asserts `affected`, because a scanner has no basis for an all-clear. |
| [SPDX 3.0.1](https://docs.airom.dev/output/formats) | A JSON-LD graph with the AI, Dataset, Software, and Security profiles. Lossiest format: SPDX has no slot for `file:line` evidence, and the document says so rather than letting you assume there was none. |
| [AIBOM diff](docs/cli.md) | The semantic delta between two scans, so AI becomes a per-PR control. |
| [Test scope](https://docs.airom.dev/concepts/test-scope) | Fixtures and test trees are recorded but kept out of the default view. |
| [Signed rule updates](https://docs.airom.dev/rules/updates) | New frameworks reach you without a new binary, over an ed25519-verified channel. |

## In CI

```yaml
- run: pip install airom
- run: airom scan . --exit-code 1 --fail-on "risk:high|cve:critical" -o sarif=airom.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: airom.sarif }
```

Findings land as GitHub Code Scanning alerts on the pull request that introduced
them. See **[exit codes](docs/cli.md#exit-code-contract)** and
**[GitHub Actions](https://docs.airom.dev/ci/github-actions)**.

## Extending it

Model IDs churn weekly, so the fast-moving surface lives in **YAML rule packs**
rather than Go. Adding a provider is a rules PR, not a release:

```bash
airom dev new-rulepack fireworks   # scaffolds the pack and fixture stubs
airom rules lint rules/models/fireworks.yaml
```

One YAML file, two fixtures, one golden. For detections needing a real parser,
implement `FileDetector` against the stdlib-only `pkg/airom/detect` SDK.
See **[writing rules](docs/rule-schema.md)** and
**[docs/plugin-guide.md](docs/plugin-guide.md)**.

## Status

**v0.4.4**, early but real. The pipeline, detectors, writers, and overlays are
implemented and tested; expect rough edges.

Known gaps, each also surfaced in the affected flag's `--help`: caching is not
implemented (`--no-cache` is a no-op), live registry and daemon image pulls are
not available (use `airom image --input <archive>`), and live-cluster scanning
is not available (use `airom k8s --manifests <dir>`).

The full ledger of what is complete, what is deferred to v2, and how AIROM
compares to adjacent tools is in
**[docs/project-status.md](docs/project-status.md)**.

## Security

AIROM is a security tool whose parsers eat untrusted bytes, and is built
accordingly:

- **No model execution, ever.** Weights are identified by magic bytes and
  bounded header parsing. Nothing is loaded, deserialized, or run.
- **Fuzzed parsers.** Every binary header parser is fuzzed in CI and must return
  errors, never panic.
- **No surprise network access.** `--offline` asserts it globally.
- **Signed releases.** `CGO_ENABLED=0`, reproducible, checksummed, and
  keyless-cosign-signed.

Report vulnerabilities privately via a GitHub security advisory. See
[SECURITY.md](SECURITY.md).

## Documentation

- **[docs/cli.md](docs/cli.md)**: every command, flag, and exit code
- **[docs.airom.dev](https://docs.airom.dev)**: installation, concepts, output formats, CI recipes
  (source: [airomhq/airom-web](https://github.com/airomhq/airom-web))
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**: design and decision log
- **[docs/rule-schema.md](docs/rule-schema.md)**: the rule-pack YAML reference
- **[docs/RELEASING.md](docs/RELEASING.md)**: cutting a release (it spans two repos)

The documentation site and the landing page are built from
**[airomhq/airom-web](https://github.com/airomhq/airom-web)**.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The fastest way to help is a rule
pack. Most providers land in under an hour.

## License

[Apache License 2.0](LICENSE). © AIROM contributors
