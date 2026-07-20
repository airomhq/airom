# AIROM Architecture

> **Status:** Accepted (v1 design baseline) · **Phase:** 1 of 10 · **License:** Apache-2.0
>
> AIROM is a single static Go binary that discovers AI
> assets in a filesystem, source repository, container image, or Kubernetes workload and emits
> an AI Bill of Materials (AIBOM) — with file:line evidence, detection technique, and a
> calibrated confidence score behind every entry.
>
> This document is the canonical architecture. It was produced by researching Syft,
> gitleaks, and semgrep internals; verifying the CycloneDX 1.6/1.7 ML-BOM, SPDX 3.0.1 AI
> profile, and SARIF 2.1.0 schemas against their published specs; and adversarially reviewing
> three competing designs (extensibility-first, performance-first, data-model-first) through
> contributor, production-operations, and correctness lenses. Decisions record their losing
> alternatives in §15.

---

## 1. Vision and positioning

Every scanner in this space today is either registry-centric (generates a model card from a
HuggingFace repo you name) or proprietary and Python-centric. Nobody scans *your code* and
answers the auditor's question: **"why does your AIBOM say gpt-4.1?"**

AIROM's differentiators, in priority order:

1. **Evidence-first.** Every component carries occurrences (`file:line`, snippet, enclosing
   symbol), the detection technique, and the arithmetic behind its confidence score. AIROM
   emits CycloneDX 1.6 `evidence.identity[]` + `evidence.occurrences[]` — which no shipping
   AIBOM tool populates — and a SARIF projection for GitHub Code Scanning, from one graph.
2. **Breadth.** Hosted model APIs (OpenAI, Anthropic, Gemini, Bedrock, Azure OpenAI, Cohere,
   Mistral, Groq, Ollama…), local weights (GGUF, safetensors, ONNX, Torch, SavedModel,
   TensorRT…), embedding models, frameworks, vector databases, prompts, datasets, AI
   generation parameters, serving infrastructure, and assembled RAG pipelines.
3. **First-class operability.** One static binary (`CGO_ENABLED=0`), a familiar scanner-style CLI,
   bounded memory on any input size, incremental caching, honest degradation (a corrupt file
   becomes an `Unknown` record, never a dead scan).
4. **Contributor-first extensibility.** The fast-moving detection surface (model-ID
   vocabularies churn weekly) lives in declarative YAML rule packs; adding a provider is a
   ~40-line YAML PR with fixtures — zero Go, zero core changes, target under one hour.

## 2. Design principles (invariants)

These are enforceable properties, not aspirations. Several are CI-tested (§14).

| # | Invariant | Enforcement |
|---|-----------|-------------|
| P1 | **Read-once.** Each file's bytes are read from the source at most once; all interested detectors share that one buffer. | `filectx` API shape; contract tests |
| P2 | **Bounded everything.** Peak RSS is a function of configuration, never input size. Bounded channels, worker pool, byte-weighted I/O budget, size caps, spool caps. | perf-regression test asserts RSS ceiling |
| P3 | **Decide before you read.** Path, size, and a 32 KB header sample eliminate >95 % of files before any full content read. Rules are gated by an Aho–Corasick keyword prefilter. | dispatcher design; mandatory-keyword lint |
| P4 | **Detectors emit claims, never components.** Identity, dedup, merging, and confidence are assembler monopolies. A contributor physically cannot break identity or caching. | `Finding` type has no ID field |
| P5 | **The graph is the product; writers are pure functions** `*Inventory → []byte`. No writer invents, drops, or re-derives data. | golden files + schema conformance in CI |
| P6 | **Degradable by default.** Only source acquisition failures are fatal. Detector errors and panics degrade to first-class `Unknowns` in the output. | chaos test injects panics, asserts completion |
| P7 | **Deterministic output.** Identical inputs produce byte-identical outputs at any parallelism. | CI diffs `--parallel 1` vs `--parallel 16` |
| P8 | **Pure Go, `CGO_ENABLED=0`, forever** (release binary). | goreleaser config; CI build matrix |

## 3. System overview

```
                    ┌─────────────────────────────────────────────────────────────┐
   airom scan .     │                 SOURCE ACQUISITION (internal/source)        │
   airom fs .       │  dir ─────────► DirSource   (os, ReaderAt, gitignore)       │
   airom repo URL   │  git URL ─────► clone(depth=1) ──► DirSource                │
   airom image REF  │  OCI image ───► squashed tar stream (go-containerregistry)  │
   airom k8s        │  k8s ─────────► workload enum (client-go) ──► N × ImageSrc  │
                    └───────────────────────────┬─────────────────────────────────┘
                                                │ Source = Walker + Resolver + identity
                                                ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ PHASE 1 — STREAMING SCAN (one pass, bounded pipeline)                             │
 │                                                                                   │
 │  walker (1 producer)                                                              │
 │   · enumerate; .gitignore/.airomignore/skip globs; size triage                    │
 │   · 32 KB header read; binary sniff; language classify; magic-byte table          │
 │   · cache probe (stat-key → skip file entirely)                                   │
 │   · [tar sources] spool decision happens HERE (stream validity)                   │
 │        │ tasks chan (cap 4×workers)              ◄── backpressure                 │
 │        ▼                                                                          │
 │  worker pool (N = GOMAXPROCS)                                                     │
 │   · selector index → interested detectors only                                    │
 │   · lazy ONE full bounded read, tee-hashed (xxh3 + SHA-256) — P1                  │
 │   · matched detectors run SEQUENTIALLY on the shared buffer                       │
 │   · rule engine: region lexer → Aho–Corasick → gated regex → Findings             │
 │   · panic/error per file → Unknown, scan continues — P6                           │
 │        │ results chan (cap 256)                                                   │
 │        ▼                                                                          │
 │  collector (exactly 1 goroutine, zero locks)                                      │
 │   · accumulate Findings; build ProjectIndex (summaries only, never content)       │
 │   · async batched cache writes (flushed before phase barrier)                     │
 └───────────────────────────────┬──────────────────────────────────────────────────┘
                                 │ barrier: walker + workers drained, cache flushed
                                 ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ PHASE 2 — PROJECT DETECTORS (cross-file, pull-style over Resolver, flat set)      │
 │   HF model-dir assembly (config.json + weights = ONE component)                   │
 │   adapter → base-model lineage (adapter_config.json)                              │
 │   config ⇄ model binding (generation_config.yaml → CONFIGURES edge)               │
 │   manifest ⇄ lockfile joins · RAG pipeline stitching                              │
 └───────────────────────────────┬──────────────────────────────────────────────────┘
                                 ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ ASSEMBLER (single-threaded, deterministic)                                        │
 │   normalize → CanonicalKey identity → keep-and-relate merge → confidence          │
 │   calculus → param binding → relation resolution → sorted *airom.Inventory        │
 └───────────────────────────────┬──────────────────────────────────────────────────┘
                                 ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ WRITERS — pure functions, multi-output:  -o table -o cyclonedx=bom.json           │
 │   airom-json (native, versioned schema) │ cyclonedx 1.6 │ sarif 2.1 │ yaml │ table│
 │   spdx-3.0.1 AI profile: v2 slot (model already carries everything it needs)      │
 └──────────────────────────────────────────────────────────────────────────────────┘
```

The two-phase split is first-class from day one. Streaming-only scanners have had to retrofit
post-analysis passes when cross-file logic appeared; AIROM's core detections
(`config.json` naming a model next to `model.safetensors`, PEFT adapters referencing base
models, RAG assembly) are cross-file-shaped, so phase 2 exists from the first commit. The
phase-2 set is deliberately **flat**: one barrier, every project detector sees the same
immutable phase-1 findings view. No inter-detector ordering or dependency declarations —
anything needing multi-stage reasoning belongs in the assembler.

## 4. Repository layout

One Go module (the premature-repo-split lesson: split nothing until external demand
exists). Module path: `github.com/airomhq/airom`.

The `pkg/` vs `internal/` line **is** the extensibility contract: `pkg/airom/...` is the
plugin SDK — semver-guarded (apidiff in CI), shipped as v0.x until the interfaces survive
real third-party use. Everything else is `internal/` and free to refactor.

```
airom/
├── cmd/airom/                  # main.go only: version stamp → internal/cli
├── pkg/airom/                  # ── PUBLIC API (plugin SDK), stdlib-only deps ──
│   ├── (root)                  # domain model: Inventory, Component, Evidence, Occurrence,
│   │                           #   Relationship, kinds, Confidence, tri-states (§5)
│   ├── detect/                 # Detector/ProjectDetector interfaces, Finding, Selector,
│   │                           #   FileInput contract (§6)
│   ├── purl/                   # purl construction/normalization for ML types (§9.4)
│   └── detectortest/           # contract-test + golden-file harness for detector authors (§14)
├── internal/
│   ├── cli/                    # cobra tree, koanf config binding, exit-code policy
│   ├── app/                    # composition root: the ONLY wiring site (§12)
│   ├── engine/                 # phase scheduler, worker pools, collector, catalog
│   ├── source/                 # Source implementations (§7)
│   │   ├── dirsource/          #   fastwalk + nested-gitignore stack + .airomignore
│   │   ├── gitsource/          #   shallow clone (exec-git fast path, go-git fallback) → dirsource
│   │   ├── imagesource/        #   go-containerregistry squashed-tar streaming + spool
│   │   └── k8ssource/          #   client-go workload enum → imagesource; offline manifest mode
│   ├── filectx/                # read-once FileContext: shared header, lazy tee-hashed content (§8)
│   ├── dispatch/               # compiled selector index (basename/ext/glob/magic tables)
│   ├── classify/               # language / MIME / binary classification, magic-byte registry
│   ├── ruleengine/             # YAML rule compiler, Aho–Corasick trie, generic rule detector
│   │   └── lexer/              #   per-language code/comment/string region classifiers (~250 LOC each)
│   ├── detectors/              # built-in CODE detectors (one package per concern)
│   │   ├── modelfile/          #   gguf, safetensors, onnx, torchzip+picklewalk, savedmodel,
│   │   │                       #   tensorrt, tflite, h5 — header-only parsers, core IP
│   │   ├── manifest/           #   requirements/pyproject/package.json/go.mod/pom/gradle-lock/
│   │   │                       #   Cargo.toml/csproj → AI framework & SDK components
│   │   ├── gosrc/              #   stdlib go/parser AST detector for Go source
│   │   ├── prompt/             #   prompt files (txt/md/yaml/jinja), template heuristics
│   │   ├── dataset/            #   CSV/JSONL/Parquet/Arrow signatures
│   │   ├── infra/              #   Dockerfile/compose/k8s-manifest AI-infra signals
│   │   ├── project/            #   phase-2: hfdir, adapterlink, configbind, raglink, lockjoin
│   │   └── all/                #   GENERATED registration list (go generate) — no hand-edited hotspot
│   ├── assemble/               # identity, merge, confidence calculus, param binder, relation resolver
│   ├── cache/                  # bbolt: two-tier file cache + per-layer blob cache (§10)
│   ├── writer/                 # nativejson/, cdx/, sarifw/, yamlw/, tablew/ (§11)
│   ├── xio/                    # pooled buffers, spool (mem→tmpfile), clamped byte-semaphore
│   └── metrics/                # ScanStats, per-detector timings, --pprof/--trace bootstrap
├── rules/                      # ── EMBEDDED RULE PACKS (go:embed) — the contributor hot zone ──
│   ├── models/                 #   openai.yaml anthropic.yaml gemini.yaml bedrock.yaml
│   │                           #   azure-openai.yaml cohere.yaml mistral.yaml groq.yaml ollama.yaml
│   ├── embeddings/             #   openai.yaml sentence-transformers.yaml bge-e5-minilm.yaml voyage.yaml
│   ├── frameworks/             #   langchain.yaml llamaindex.yaml haystack.yaml dspy.yaml crewai.yaml
│   │                           #   autogen.yaml semantic-kernel.yaml transformers.yaml vllm.yaml mlflow.yaml
│   ├── vectordb/               #   chroma.yaml milvus.yaml qdrant.yaml pinecone.yaml weaviate.yaml
│   │                           #   faiss.yaml pgvector.yaml redis.yaml elastic.yaml mongodb-atlas.yaml
│   ├── infra/                  #   ollama.yaml vllm.yaml tgi.yaml rayserve.yaml sagemaker.yaml
│   │                           #   vertex.yaml azureml.yaml
│   ├── params/                 #   generation-parameter capture rules
│   ├── prompts/                #   PromptTemplate/ChatPromptTemplate/system_prompt patterns
│   └── datasets/               #   load_dataset(), kaggle refs, HF dataset ids
├── docs/                       # this file, plugin-guide.md, rule-schema.md, mapping.md, cli.md
├── schemas/                    # native output JSON Schema, versioned (airom-v1.schema.json)
└── testdata/fixtures/          # miniature polyglot repos + golden outputs per writer (§14)
```

Layout rules (lint-enforced):
- `internal/*` may import `pkg/airom/*`; **never** the reverse.
- `pkg/airom` and `pkg/airom/detect` import nothing outside the stdlib.
- **One rule pack file per provider**, never per-category monoliths — with hundreds of rules,
  monolithic packs are merge-conflict hotspots and defeat CODEOWNERS review routing.
- The rule-pack YAML schema stays `internal/` in v0 (contributors edit YAML, not Go); it
  graduates to `pkg/` when stable.

## 5. Core domain model (`pkg/airom`)

The canonical graph is designed as a superset of what CycloneDX 1.6 ML-BOM, SPDX 3.0.1 AI
profile, SARIF 2.1.0, and the native format need, so every writer is a pure projection. Three
spec facts drive the shape:

1. **CycloneDX 1.6 `evidence.identity[]` + `evidence.occurrences[]`** is the only BOM-native
   home for "seen at file:line, by technique T, with confidence C." Our `Evidence` type is its
   superset.
2. **SPDX 3.0.1 is an element graph with required fields we often can't know**
   (`suppliedBy`, `downloadLocation`, `builtTime`) → the model is a graph with typed edges and
   distinguishes *unknown* from *not-applicable* (tri-state → deterministic `NOASSERTION`).
3. **SARIF wants one rule per detector, one result per occurrence, stable fingerprints** →
   occurrences carry their detector ID; component identity is a stable hash.

```go
package airom

// ID: "airom:" + hex(sha256(CanonicalKey))[:16] — seeds bom-ref (CDX), spdxId (SPDX),
// and partialFingerprints (SARIF). Minted ONLY by the assembler (§9).
type ID string

type ComponentKind string

const (
    KindHostedLLM      ComponentKind = "hosted-llm"       // API model ref: gpt-4.1, claude-*
    KindLocalModelFile ComponentKind = "local-model-file" // weights on disk/in image
    KindEmbeddingModel ComponentKind = "embedding-model"  // hosted or local, embedding task
    KindFramework      ComponentKind = "framework"        // langchain, transformers, vllm…
    KindLibrary        ComponentKind = "library"          // SDKs: openai, anthropic, google-genai
    KindVectorDB       ComponentKind = "vector-db"
    KindPrompt         ComponentKind = "prompt"
    KindDataset        ComponentKind = "dataset"
    KindAIConfig       ComponentKind = "ai-config"        // unbound generation params (§9.5)
    KindInfra          ComponentKind = "infra"            // serving infra: ollama, vllm, tgi…
    KindService        ComponentKind = "service"          // remote endpoint: azure deployment, bedrock
    KindRAGPipeline    ComponentKind = "rag-pipeline"     // synthesized composite
    KindApplication    ComponentKind = "application"      // scan root
)

// DetectionMethod aligns 1:1 with the CycloneDX evidence technique enum.
type DetectionMethod string

const (
    MethodSourceCode  DetectionMethod = "source-code-analysis"
    MethodAST         DetectionMethod = "ast-fingerprint"
    MethodManifest    DetectionMethod = "manifest-analysis"
    MethodBinary      DetectionMethod = "binary-analysis"   // magic bytes + header parse
    MethodHash        DetectionMethod = "hash-comparison"   // known-weights digest match
    MethodConfig      DetectionMethod = "config-analysis"   // yaml/toml/env/dockerfile
    MethodFilename    DetectionMethod = "filename"
    MethodAttestation DetectionMethod = "attestation"       // v2: sigstore/in-toto verified
)

type Confidence float64 // 0..1; Band() → high ≥0.9 / medium ≥0.6 / low

// ── Tri-state optionals: the SPDX NOASSERTION discipline ────────────────────
// Confined to fields SPDX/CDX actually need it for; not pervasive.
type Presence uint8
const (
    Absent  Presence = iota // does not apply → omit everywhere
    Unknown                 // applies but undetermined → SPDX NOASSERTION
    Known
)
type OptString struct{ P Presence; V string }
type OptInt64  struct{ P Presence; V int64 }
type OptTime   struct{ P Presence; V time.Time }
type TriState  uint8 // Yes / No / Unknown

// ── Evidence: the atom is the Occurrence ────────────────────────────────────

type Location struct {
    Path      string // source-root-relative, forward slashes, always set
    Line      int    // 1-based (SARIF convention); 0 = whole-file
    EndLine   int
    Column    int    // 1-based UTF-16 code units (SARIF columnKind); 0 = unknown
    EndColumn int
    Layer     string // OCI layer digest when attributable; "" otherwise (v2 fills)
}

// Occurrence: one sighting by one detector — the "why is this in my AIBOM" answer.
type Occurrence struct {
    Location   Location
    DetectorID string            // stable: "rules/openai/model-literal" → SARIF ruleId
    Method     DetectionMethod
    Confidence Confidence        // this sighting alone
    Snippet    string            // matched text, ≤200 bytes, sanitized
    Symbol     string            // enclosing func/class if known
    Fields     map[string]string // extracted bindings: {"model":"gpt-4.1","temperature":"0.2"}
}

// IdentityClaim: contested per-field identity, preserved — never silently discarded.
// A version from a lockfile (0.95) beats one from a comment (0.3); the loser is
// retained and emitted as a competing CycloneDX evidence.identity[] entry.
type IdentityClaim struct {
    Field      string          // name | version | purl | hash (CDX identity field enum)
    Value      string
    Confidence Confidence
    Methods    []DetectionMethod
}

type Evidence struct {
    Occurrences []Occurrence
    Identity    []IdentityClaim
}

// ── Component ────────────────────────────────────────────────────────────────

type Hash struct{ Alg, Hex string } // "SHA-256", "XXH3" (cache-internal)
type KV struct{ Name, Value string }

type Component struct {
    ID       ID
    Kind     ComponentKind
    Name     string    // canonical, post-normalization: "gpt-4.1", "meta-llama/llama-3-8b"
    Group    string    // org/namespace: "openai", "meta-llama"
    Version  OptString
    Provider OptString // "openai","anthropic","huggingface","aws-bedrock","local"…
    PURL     string    // spec types ONLY; empty for hosted API models (§9.4)
    Licenses []License
    Supplier *Party    // → CDX supplier / SPDX suppliedBy

    // Provenance & integrity
    Hashes           []Hash    // always computed for local model files (free via tee-hash)
    DownloadLocation OptString // tri-state → SPDX required field
    SourceInfo       string    // human trail: "declared in requirements.txt; loaded in src/rag.py"
    ReleaseTime      OptTime

    // Facets — exactly one non-nil per kind family (assembler-validated)
    Model   *ModelFacet   // hosted-llm | local-model-file | embedding-model
    Data    *DataFacet    // dataset | prompt
    Infra   *InfraFacet   // infra | service
    Package *PackageFacet // framework | library

    Confidence Confidence // assembled (§9.3) — never detector-set
    Evidence   Evidence
    Props      []KV       // overflow → CDX properties, "airom:" namespace

    Attestations []AttestationRef // v2 fills; writers already map (recorded, not verified)
}

type ModelFacet struct {
    Task             OptString    // "text-generation","embedding","rerank"
    Architecture     OptString    // gguf general.architecture / config.json model_type
    ParamCount       OptInt64     // exact, from GGUF/safetensors headers
    Quantization     OptString    // "Q4_K_M","F16"
    ContextLength    OptInt64
    Format           OptString    // "gguf","safetensors","onnx","torch-pickle",…
    BaseModel        OptString    // adapter lineage → also a DERIVED_FROM edge
    GenerationParams []BoundParam // §9.5 — params with provenance
    PickleRisk       *PickleRisk  // suspicious GLOBAL opcodes (security differentiator)
    Card             *ModelCard   // CDX modelCard superset: metrics, considerations, energy
}

// BoundParam: a generation parameter with its own provenance. Two call sites with
// different temperatures are two BoundParams — never merged, never averaged.
type BoundParam struct {
    Name       string      // "temperature"
    Value      string      // "0.2"
    Occurrence *Occurrence // where it was bound
}

// ── Relationships: typed, evidenced edges ────────────────────────────────────

type RelType string

const (
    RelUses        RelType = "uses"         // app USES hosted-llm
    RelDependsOn   RelType = "depends-on"   // app DEPENDS_ON framework (manifest)
    RelServedBy    RelType = "served-by"    // model SERVED_BY infra
    RelQueries     RelType = "queries"      // retriever QUERIES vector-db
    RelEmbedsWith  RelType = "embeds-with"  // rag-pipeline EMBEDS_WITH embedding-model
    RelPromptedBy  RelType = "prompted-by"  // hosted-llm PROMPTED_BY prompt
    RelTrainedOn   RelType = "trained-on"   // model TRAINED_ON dataset (SPDX trainedOn)
    RelDerivedFrom RelType = "derived-from" // LoRA adapter DERIVED_FROM base model
    RelConfigures  RelType = "configures"   // config file CONFIGURES model/infra
    RelContains    RelType = "contains"     // rag-pipeline CONTAINS retriever/store
)

type Relationship struct {
    From, To   ID
    Type       RelType
    Confidence Confidence
    Evidence   []Occurrence // the call site proving the edge, not just the endpoints
}

// ── The document ─────────────────────────────────────────────────────────────

type Inventory struct {
    SchemaVersion string         // "1" — the native JSON is a versioned API from release one
    Tool          ToolInfo       // name, version, commit
    Serial        string         // uuid → CDX serialNumber (injectable for goldens)
    Timestamp     time.Time      // injectable clock
    Lifecycle     string         // "pre-build" (source) | "post-build" (image)
    Source        SourceInfo     // type, path/ref/digest, git remote+commit+dirty, k8s context
    Root          ID             // the application component
    Components    []Component    // sorted by ID — deterministic
    Relationships []Relationship // sorted (From, Type, To)
    Unknowns      []Unknown      // "looked relevant, couldn't parse" — honesty over silence
    Stats         ScanStats      // files walked/skipped, bytes read, cache hits,
}                                // per-detector ns + invocations, selection explanation

type Unknown struct{ Path, DetectorID, Reason string }
```

This satisfies the required component schema field-for-field: Name, Type (Kind), Version,
Provider, Source (SourceInfo + Occurrence), Location/File/Line (Occurrence.Location),
Framework (PackageFacet + RelDependsOn), License, Provenance (SourceInfo/DownloadLocation/
Supplier), Checksum/Hash, Confidence, Detection Method, Metadata (Props/Facets).

## 6. Detection framework

### 6.1 Detector interfaces (`pkg/airom/detect`)

```go
package detect

// Selector: declarative interest. The dispatcher compiles ALL selectors into one
// index evaluated once per file — O(matches), never O(detectors) per file.
type Selector struct {
    Basenames  []string // "requirements.txt", "config.json"   → O(1) map hit
    Extensions []string // ".py", ".gguf"                      → O(1) map hit
    PathGlobs  []string // "**/prompts/**" (doublestar) — kept rare
    Languages  []Language
    Magic      []Magic  // {Offset, Bytes} matched against the shared header sample
    MaxSize    int64    // 0 = category default (text 1 MiB; header-only unlimited)
    Need       Needs    // Stat | Header | Content — drives read & spool policy
}

type Detector interface {
    ID() string        // stable, namespaced: "modelfile/gguf", "rules/openai"
    Version() int      // participates in cache keys; CI checks "detector diff ⇒ bump"
    Selector() Selector
}

// FileDetector: phase 1 — one file at a time, streaming.
type FileDetector interface {
    Detector
    DetectFile(ctx context.Context, f *File) ([]Finding, error) // errors → Unknowns
}

// ProjectDetector: phase 2 — cross-file, pull-style. Flat set, one barrier,
// all see the same immutable phase-1 findings view.
type ProjectDetector interface {
    Detector
    DetectProject(ctx context.Context, r Resolver, prior FindingsView) ([]Finding, error)
}

// File: read-once access. Header() is the shared 32 KB sample; Content() performs
// THE single bounded read (tee-hashed); ReaderAt() works on dir sources and returns
// ErrNotSeekable on stream sources — the asymmetry is explicit, not papered over.
type File struct { /* path, size, lang, magic id; Header(); Content(); ReaderAt() */ }

// Resolver: phase-2 pull API, source-agnostic (dir/image/repo/k8s).
type Resolver interface {
    FilesByGlob(pattern ...string) ([]FileRef, error)
    Open(ref FileRef) (io.ReadCloser, error)
    Stat(path string) (FileRef, error)
}

// Finding = claims, not components (P4). The assembler owns identity.
type Finding struct {
    Claim      ComponentClaim  // kind, raw name/group/version/provider, partial facet, hashes
    Occurrence airom.Occurrence
    Relations  []RelationClaim // edges are first-class detector output
}

// RelationClaim: how detectors produce edges. TargetHint is resolved by the
// assembler AFTER all components exist; a LocalRef links two claims made by the
// same detector in the same file. Dangling hints become Stats warnings — never
// phantom nodes, never guessed edges.
type RelationClaim struct {
    Type       airom.RelType
    TargetHint TargetHint // {Kind, Name} | {Kind, FromField: "model"} | LocalRef
}
```

Granularity: one detector = one *format or provider concern* (the GGUF parser; the LangChain
rule pack) — not one per file type, not a mega-detector per language.

### 6.2 Registration and selection

**Explicit catalog, composed in the composition root — no `init()` magic.**

- Built-in code detectors are listed in `internal/detectors/all/all.go`, which is
  **generated** (`go generate`) — no hand-edited central file for every PR to conflict on.
- Rule-engine detectors are constructed explicitly with the compiled `*Matcher` as a
  constructor argument — no globals, no two-sources-of-truth wiring.
- Duplicate detector IDs panic at startup (fails in CI, never silently shadows).
- Selection uses Syft's proven tag/expression grammar: defaults per source type, then
  `--select "python,+modelfile/gguf,-dataset"`. Which expression enabled which detector is
  recorded in `Inventory.Stats` (auditability).
- Library embedders pass their own detectors to the engine constructor — the same explicit
  path, deterministic for tests.

### 6.3 Declarative rule packs — the bright line

> **The rule: if the detection is expressible as *keywords + regex over classified text
> regions + a templated claim*, it's YAML. The moment you need a loop, a parser, or two
> files, it's Go.**

Declarative (≈80 % of the detection surface, 100 % of the fast-moving surface): hosted-model
IDs, SDK call-site patterns, framework/vector-DB usage, embedding-model names, prompt-template
usage, generation params, infra client usage. A new model ID is a **rules PR, never a
release**.

Code: binary header parsers, pickle opcode walking, manifest parsers, HF directory assembly,
Go AST analysis, all phase-2 detectors.

```yaml
# rules/models/openai.yaml — one file per provider (review routing, no merge conflicts)
pack: openai
version: 4                      # informational; the CONTENT hash drives cache keys
rules:
  - id: openai/model-literal
    kind: hosted-llm
    provider: openai
    languages: [python, javascript, typescript, go, java, rust, csharp, kotlin]
    keywords: ["gpt-", "o3", "o4-", "chatgpt-"]   # Aho–Corasick prefilter — MANDATORY
    pattern: '\bmodel\s*[:=]\s*["''](?P<model>gpt-[\w.\-]+|o[34][\w.\-]*)["'']'
    regions: [code, string]                        # never match inside comments
    claim: { name: "${model}" }
    confidence: 0.85

  - id: openai/chat-call
    kind: library
    provider: openai
    keywords: ["chat.completions.create", "responses.create"]
    pattern: '\.(chat\.completions|responses)\.create\s*\('
    claim: { name: "openai-sdk" }
    relations:                                     # edges from YAML — no Go needed
      - { type: uses, target: { kind: hosted-llm, from_field: model } }
    capture_params:                                # same-call-site binding (§9.5)
      within_lines: 12
      names: [temperature, top_p, top_k, max_tokens, max_output_tokens, seed,
              stop, reasoning_effort, response_format]
    confidence: 0.7
```

Compilation (gitleaks lineage): `rules.Compile()` runs **once at startup** — validates every
pack (unique IDs across all packs, regexes compile, named groups referenced by templates
exist, **keywords non-empty: the linter rejects keyword-less rules**, so nobody ships an
un-prefiltered regex), then builds **one Aho–Corasick trie over all packs' keywords**. Per
file: the region lexer classifies code/comment/string; the trie runs over code+string regions;
only regexes whose keywords hit ever execute. Hundreds of rules × 100k files stays cheap
because the regex engine is literal-gated (the shape gitleaks and semgrep both proved).

Three rule layers: **embedded defaults** (`go:embed`, offline, versioned with the binary) →
**user overlay** (`--rules extra.yaml`; merge by ID: add/override/disable) → **remote
registry** (v2, OCI-distributed, pairs with signing work). The SHA-256 of the *effective
compiled ruleset* participates in every cache key — rules-as-data is self-invalidating,
which structurally eliminates the forgotten-`Version()`-bump stale-cache bug for the
entire fast-moving surface.

Every rule ships **≥1 positive and ≥1 negative fixture**, enforced by `airom rules lint`
in CI (semgrep-style hygiene).

### 6.4 The pure-Go language strategy

- Per-language **region lexers** (~250 LOC each: code/comment/string classification for
  Python, JS, TS, Java, Rust, C#, Kotlin) + the rule engine. Not parsers, not ASTs.
- **Go source** uses stdlib `go/parser` — free, exact AST.
- **wazero-WASM tree-sitter** is a reserved precision slot behind the existing `FileDetector`
  seam — adopted only when the oracle scoreboard (§14) shows measured precision failures.
- **CGO tree-sitter never ships**: it lives behind `//go:build oracle` as a dev-time accuracy
  oracle in a dedicated CI job, tracking precision/recall of the lexer+regex core against
  real ASTs. The WASM-layer decision is evidence-driven, not faith-based.

### 6.5 The one-hour contributor story (north star, documented + CI-verified)

1. `airom dev new-rulepack fireworks` scaffolds `rules/models/fireworks.yaml` + fixtures.
2. Author writes ~30 lines of YAML: keywords, two patterns, a claim template; adds a `.py`
   and a `.ts` fixture (positive + negative).
3. `airom rules lint && go test ./rules/... -run Fireworks -update` writes the golden.
4. PR = 1 YAML + 2 fixtures + 1 golden. Zero Go. Review = "do the goldens look right."

The code path is nearly as short: implement `FileDetector`, add to the generated list,
wire `detectortest.Run`. `docs/plugin-guide.md` walks both with real diffs.
`airom detectors list/explain` prints every detector's ID, version, tags, and exactly what
it looks at — capability-as-data makes the scanner self-documenting.

## 7. Source abstraction (`internal/source`)

The interface is shaped by the **worst** source — a squashed OCI tar stream: sequential,
non-seekable, consume-during-walk. The directory case is the easy specialization.

```go
type Source interface {
    Name() string
    Kind() Kind          // dir | repo | image | k8s
    ID() string          // content identity: image digest / git HEAD / dir realpath
    LayerIDs() []string  // image: diff IDs (blob-cache granularity); else one pseudo-blob
    Walker() Walker      // push-style enumeration, ignore-aware
    Resolver() Resolver  // pull-style (phase 2); tar sources serve from the phase-1 spool
    Info() SourceInfo    // provenance: git remote+commit+dirty, digest, k8s context
    Close() error
}
```

- **dirsource** — fastwalk enumeration; per-directory nested `.gitignore` stack
  (gocodewalker semantics) + `.airomignore` + default skips (`.git`, `node_modules`,
  `vendor`, virtualenvs); 8 KB NUL-sniff for binary; symlink cycles guarded by (dev,inode);
  permission errors → `Unknowns`, never fatal.
- **gitsource** — `git clone --depth=1 --single-branch --no-tags` via exec-git fast path when
  a git binary exists, go-git v6 fallback; then *delegates entirely to dirsource*. Local
  repos scan as plain filesystems; go-git metadata feeds provenance.
- **imagesource** — go-containerregistry `v1.Image` (remote → daemon → tarball → OCI-layout
  fallback chain), `mutate.Extract` squashed tar streamed **once**. Content discipline:
  - Header reads and **spool decisions execute in the walker goroutine** — tar entry content
    is only valid during traversal (this is a hard stream-validity constraint; workers
    consume spooled buffers, never the live stream).
  - Spool caps: ≤4 MiB in memory, ≤64 MiB tmpfile, else header-only.
  - The **union of phase-2 ProjectDetector selectors is folded into the spool policy**, so a
    phase-2 detector's globs are visible in image scans (closes the stream-visibility hole).
  - Large model files are **tee-hashed during the discard copy** — the stream must be
    consumed anyway, so content-hash identity for in-image weights is free (repairs the
    weights-identity story for images, §9.1).
  - Torch `.pt` zips are detected from **local file headers** encountered sequentially, not
    the central directory — streams can't seek to EOF.
  - A 40 GB GGUF inside an image costs a 32 KB header parse + a hashing discard-copy:
    zero memory growth, zero disk.
- **k8ssource** — client-go typed clients enumerate Deployments/StatefulSets/DaemonSets/
  Jobs/CronJobs/Pods (paginated, deduped by ownerRefs), extract `containers[] +
  initContainers[] + ephemeralContainers[]` images, dedupe refs, fan each unique image into
  imagesource (serial by default; `--parallel-images` opt-in). Offline mode scans manifest
  YAML/Helm output with the same extraction code.

One resolver abstraction means every detector — including third-party — is automatically
source-agnostic.

## 8. Concurrency model

Reference topology (spelled out because the details are where deadlocks live):

```go
g, ctx := errgroup.WithContext(rootCtx)
tasks   := make(chan fileTask, 4*workers)   // workers = --parallel, default GOMAXPROCS
results := make(chan fileResult, 256)

// 1) Exactly ONE producer owns and closes `tasks`. For tar sources, header reads
//    and spool decisions happen here (stream validity). Cache stat-probes happen
//    here (hit ⇒ cached findings emitted, file never enters the pipeline).
g.Go(func() error { defer close(tasks); return src.Walker().Walk(ctx, enqueue) })

// 2) Worker pool: all matched detectors for one file run SEQUENTIALLY in one
//    worker on one shared buffer (read-once, zero synchronization). Parallelism
//    is across files — never per-(file,detector) goroutines.
var wg sync.WaitGroup
for i := 0; i < workers; i++ { wg.Add(1); g.Go(worker) } // wg.Done in worker defer
go func() { wg.Wait(); close(results) }()                // close after ALL workers exit

// 3) Exactly ONE collector goroutine owns all mutable aggregation state. No locks.
//    Async batched cache writes are FLUSHED AND JOINED before the phase barrier.
g.Go(collect)

_ = g.Wait()
// ── hard phase barrier ──
// 4) Phase 2: ProjectDetectors on errgroup.SetLimit(workers), pulling via Resolver,
//    emitting into a FRESH results channel with a second collector pass.
//    (Channels do not reopen; the barrier is explicit.)
// 5) Assembler: single-threaded, deterministic. Writers: pure functions.
```

Bounds and failure rules:

- **Backpressure by construction**: bounded channels mean a fast walker cannot outrun slow
  analysis; memory is O(buffers + in-flight), independent of tree size (P2).
- **Byte-weighted I/O semaphore** (default 256 MiB budget), separate knob from CPU
  parallelism; acquired at **`min(size, budget)`** around any read >1 MiB — the unclamped
  variant is a latent deadlock on a 40 GB file (this clamp is contract-tested).
- **Buffer pooling**: `sync.Pool` per size class; findings copy out ≤200-byte snippets, never
  retain buffers.
- **Cancellation**: `errgroup.WithContext` everywhere; Ctrl-C or fatal source error cancels;
  workers observe ctx between files.
- **Fatal vs degradable** (P6): source-acquisition errors are fatal; everything downstream —
  detector panic (recovered per file with `debug.Stack()`), unreadable file, corrupt header —
  degrades to `Unknowns`. One weird YAML must never kill a 10 GB scan.
- **Determinism** (P7): the assembler sorts everything; output ordering never depends on
  scheduling. CI proves byte-identical output at `--parallel 1` vs `16`.

## 9. Assembly: identity, dedup, confidence, params

### 9.1 Identity — `CanonicalKey`

```go
type CanonicalKey struct {
    Class    string // identity class — NOT kind: "hosted-model","weights-file","package",
                    // "vecdb","prompt","dataset","infra"…
    Provider string // normalized
    Name     string // per-class normalizer chains: HF ids lowercased; OpenAI date suffixes
                    // split into version claims ("gpt-4.1-2026-01-14" ⇒ "gpt-4.1" + claim);
                    // package names PEP-503-normalized; paths cleaned
    Disc     string // discriminator: weights-file ⇒ CONTENT HASH (identity = bytes);
                    // package ⇒ ecosystem
}
func (k CanonicalKey) ID() airom.ID // "airom:" + hex(sha256(class|provider|name|disc))[:16]
```

Deliberate subtleties (each fixes a real dedup bug found in review):

- **Class ≠ Kind.** `hosted-llm` and `embedding-model` share class `hosted-model`, so
  `text-embedding-3-large` seen by an embeddings rule *and* a generic OpenAI rule collides
  into **one** component; kind resolves by facet-specificity precedence (documented order:
  embedding evidence > generic model evidence). Keying on Kind would mint twins.
- **Weights-file identity = content hash.** The same `llama.gguf` at three paths is one
  component with three occurrences; two different files sharing a basename never merge.
  Available even in image scans via tee-hash-during-discard (§7).
- **Version-unknown folding** (merge law): a versionless sighting folds into an existing
  versioned component of the same (class, provider, name) as extra evidence rather than
  minting a twin; versionless-only components emit SPDX `NOASSERTION`.
- **Alias canonicalizers are data**: per-provider alias tables ship alongside rule packs
  (`claude-sonnet-4-5` ≡ `claude-sonnet-4.5`) and feed the normalizer chains.
- **purl is an OUTPUT of identity, never the root.** Purl-first hashing causes split-brain
  dedup between purl-emitting and purl-less detectors.

### 9.2 Merge — keep-and-relate

Findings group by ID and fold: occurrences concatenate (dedup by Path+Line+DetectorID, then
sort); scalar conflicts resolve by per-field identity-claim confidence with **losers retained
as `IdentityClaim`s** (→ competing CDX `evidence.identity[]` entries — the spec models
contested identity; use it); facets merge field-wise `Known > Unknown > Absent`, with
impossible conflicts (two ParamCounts for one content hash) demoting to Unknown + a logged
warning. Nothing is deleted at merge time; filtering (`--min-confidence`) is a
presentation-layer concern.

### 9.3 Confidence calculus — grouped noisy-OR

```
Step 1  per-detector group:  g_d = max(c_i) + (1 − max(c_i)) · min(0.05·(n_d − 1), 0.15)
        (12 sightings of one regex ≈ one sighting, slightly reinforced — repetition
         cannot launder into certainty)
Step 2  bucket by DetectionMethod, noisy-OR the per-method maxima:
        C = 1 − Π_j (1 − m_j)      (independent channels corroborate)
Step 3  clamp 0.99. Only MethodHash against a known-weights digest — or a v2
        verified attestation — may assert 1.0.
```

Worked examples: `gpt-4.1` regex literal (0.85) in 12 files → ≈0.87. A GGUF found by
extension (0.5, filename) then confirmed by magic+header parse (0.95, binary-analysis) →
1−(0.5·0.05) = 0.975. A hundred filename-only hints saturate near 0.65 — one method bucket.
Properties (CI property-tested): order-independent, monotone, clamped.

### 9.4 purl discipline

Spec purl types **only**: `pkg:huggingface/org/name@rev` (lowercased), `pkg:generic` with
`?checksum=` for bare weight files, `pkg:oci` for images, ecosystem types (`pkg:pypi`,
`pkg:npm`, `pkg:golang`, `pkg:maven`, `pkg:cargo`, `pkg:nuget`) for packages.
**Hosted API models get NO purl** — identity via bom-ref + `airom:model.provider` /
`airom:model.id` properties. Minting `pkg:generic/openai/gpt-4.1` would misuse the spec and
pollute every purl-keyed consumer (Dependency-Track). Revisit when purl standardizes an AI
type.

### 9.5 AI-config → model attachment (layered, refusal-first)

1. **Rule-local capture** (highest precision): `capture_params.within_lines` captures kwargs
   in the same call expression into `Occurrence.Fields`; the assembler promotes fields on
   occurrences carrying a `model` binding into `ModelFacet.GenerationParams` as
   provenance-carrying `BoundParam`s.
2. **Phase-2 binder** (`configbind`) for separated configs: a `generation_config.yaml` /
   `model_config.json` becomes an `ai-config` component with a `configures` edge to the model
   it names, or to the file-scoped model when exactly one candidate exists.
3. **Refusal policy**: ambiguous bindings stay standalone `ai-config` components with a
   warning — **never a guessed edge**. Call-site capture beats the proximity window when
   both fire. Conflicting values are never merged: two call sites with different
   temperatures are two `BoundParam`s.

## 10. Caching (`internal/cache`, bbolt)

**Namespace key** — the whole cache self-invalidates on any behavior change, no manual bumps:

```
namespace = sha256(detectorVersions ‖ effectiveRulesetSHA256 ‖ sizeCaps ‖ ignoreConfig)
```

Within a namespace:

| Tier | Key | Hit means |
|------|-----|-----------|
| 1 (dir scans) | stat-key `(path, size, mtimeNs, dev, inode)` | **zero reads** — file never opened |
| 2 (dir scans) | content-key `xxh3` (free from the read tee) | skip detector CPU |
| blob (images) | layer diff-ID + namespace, `MissingBlobs`-shaped API | unchanged base layers never re-stream |

Rules with teeth:

- **Cache pre-assembly findings only — never assembled inventories.** Assembly logic evolves
  fastest; caching its output creates a stale-output class of bug.
- bbolt is single-writer: lock acquisition is **try-acquire, degrading to no-cache with a
  warning** — a second concurrent run must never hang CI.
- Async batched writes are flushed and joined before the phase barrier.
- `Version() int` stays on code detectors for cross-release hygiene, with a CI check
  "detector code diff ⇒ version bump."
- Honest docs: the stat tier is dead on fresh CI checkouts (mtimes reset) — CI wins come from
  the layer blob cache and the content tier. `airom clean` is the escape hatch.
- The `MissingBlobs`-shaped interface keeps a remote/shared cache backend possible (v2).

## 11. Output writers (`internal/writer`)

```go
type Writer interface {
    Format() string // json | cyclonedx | sarif | yaml | table
    Write(ctx context.Context, inv *airom.Inventory, out io.Writer) error // pure
}
```

The Inventory is small (components, not files) — streaming discipline applies to scanning,
not rendering. Multi-output: repeatable `-o fmt[=path]` (table to TTY + CycloneDX to file +
SARIF to file in one scan).

- **airom-json** — native, versioned (`schemaVersion: "1"`), JSON Schema published per
  release in `schemas/`; the lossless round-trip reference format.
- **cyclonedx** — via `CycloneDX/cyclonedx-go`; **1.6 default** (`--cdx-version 1.7` opt-in;
  modelCard shape is identical in 1.6/1.7). Model kinds → `machine-learning-model` +
  `modelCard` (params, hyperparams, considerations, energy); dataset/prompt → `data`;
  framework/library → native types; `evidence.identity[]` from IdentityClaims (confidence +
  technique) and `evidence.occurrences[]` from Occurrences (file/line/snippet — the
  differentiator no other tool emits); `depends-on` → `dependencies[]`; `trained-on` →
  `modelCard.modelParameters.datasets[].ref`; remaining edge types → documented `airom:rel.*`
  properties until CDX grows typed relationships. Overflow → `airom:*` properties.
- **sarif** — via `owenrumney/go-sarif/v3`; a pure projection of Evidence: one rule per
  DetectorID (stable vocabulary), one result per occurrence, default `level:"note"`
  (GitHub-compatible) with `--sarif-strict-kinds` for spec-pure `kind:"informational"`,
  `partialFingerprints["airomComponentIdentity/v1"] = sha256(detectorID|componentID|path)` —
  line-free, survives code motion.
- **yaml** — native model through yaml.v3, stable key order.
- **table** — `KIND | NAME | VERSION | PROVIDER | CONF | EVIDENCE` (evidence rendered as
  `n occ`); TTY-aware; a wide mode (`writer.Options.TableWide`) expands per-component
  file:line lists.
- **spdx-3.0.1 AI profile** — reserved v2 slot. The model already carries the graph,
  tri-states, and `ai_*` field homes; the writer lands as one package with zero core
  changes — that asymmetry is the acceptance test for this architecture.

`docs/mapping.md` holds the master field-mapping table (internal → CDX path → SPDX path →
SARIF path) and is **enforced by a round-trip test**; CDX and SARIF goldens are validated
against the official schemas in CI. Spec compliance is a test, not a hope.

## 12. CLI

```
airom
├── scan <target>          # scheme auto-detect: dir | git URL | image ref (Syft-style)
├── fs <path>              # explicit nouns (scanner-style)
├── repo <url|path>
├── image <ref>            # --input tar, --platform; remote→daemon→tarball→layout chain
├── k8s [context]          # --namespace | -A; --manifests <dir> (offline mode)
├── detectors {list|explain <id>}     # the explainability view
├── rules {list|lint <file>|test <file>}
├── dev {new-rulepack <name>|new-detector <name>}   # contributor scaffolding
├── clean                  # cache maintenance
└── version

Flags: -o/--output fmt[=path] (repeatable) · --format (alias) · --select <expr>
  --rules <file> (repeatable) · --parallel N · --io-budget 256m · --max-file-size 1m
  --min-confidence f · --ignore glob · --cache-dir · --no-cache · --cdx-version
  --sarif-strict-kinds · --exit-code N · --fail-on <expr> · --offline
  --pprof[=addr] · --trace file · --stats · -v/-q
Config: .airom.yaml + AIROM_* env via koanf (flags > env > file > defaults) · .airomignore
```

**Exit-code contract** (documented loudly — SBOM scanners commonly field recurring confusion):
exit 0 = scan succeeded, findings are NOT failures; `--exit-code/--fail-on` is opt-in CI
policy.

**Wiring**: one hand-built composition root in `internal/app` (~60 lines, no DI framework):
compile rules → build catalog (explicit constructors, compiled matcher injected) → open cache
(namespace from versions + ruleset hash) → detect source → run engine → assemble → fan out
writers. `pkg/airom.Scan(ctx, target, opts)` wraps the same path for library embedders.

Stack: cobra + koanf (viper's weight/global state rejected) + stdlib slog.

## 13. Security posture

AIROM is a security tool whose parsers eat untrusted bytes; it must be hardened accordingly.

- Every binary header parser (GGUF, safetensors, ONNX, torch-zip, pickle, SavedModel, HDF5,
  TFLite) is **fuzzed in CI** and must return errors — never panic, never allocate unbounded
  (adversarial safetensors header lengths are capped; test-asserted).
- The **pickle opcode walker** statically walks `.pt`/`.pkl` streams for suspicious `GLOBAL`
  opcodes (`os.system`, `subprocess`, `builtins.eval`…) without ever executing — surfacing
  `PickleRisk` on torch components is a security differentiator, not just inventory.
- No network access during `fs`/`repo`(local)/`image --input` scans; `--offline` asserts it
  globally.
- Release binaries: `CGO_ENABLED=0`, reproducible builds, cosign-signed, SBOM +
  (dogfooded) AIBOM attached per release.
- Scanner never loads/executes model files; header parsing only.

## 14. Testing strategy

| Layer | Mechanism |
|-------|-----------|
| Detector contract | `pkg/airom/detectortest.Run(t, det, fixtures)` — public harness, same for built-ins and third parties. Asserts: golden findings match; `Selector()` actually gates; locations are 1-based; determinism (two runs identical); no panic on truncated/empty input; **runs every detector against BOTH dir-backed and tar-stream-backed inputs** (catches seekability bugs pre-merge). |
| Rule hygiene | `airom rules lint` in CI: regexes compile, keywords mandatory, template groups exist, IDs globally unique, **≥1 positive + ≥1 negative fixture per rule**. |
| Golden E2E | Fixture repos (`python-langchain-rag/`, `go-openai-service/`, `node-openai-app/`, `local-llama-gguf/` with handcrafted valid headers, `mixed-monorepo/`, `k8s-manifests/`, OCI layout built in CI) → all five writer outputs golden-filed (injected clock + serial). |
| Schema conformance | Native output vs `schemas/airom-v1.schema.json`; CDX goldens vs official `bom-1.6.schema.json`; SARIF vs OASIS schema — in CI. |
| Mapping round-trip | Fuzz-populated Inventory → native JSON → re-read → identical; CDX output parsed back to assert `docs/mapping.md` holds. |
| Assembler properties | Merge order-independence (shuffle findings ⇒ same graph), confidence monotonicity, clamp, ID stability. |
| Fuzzing | `go test -fuzz` corpora for all binary header parsers. |
| Determinism | Byte-identical output at `--parallel 1` vs `16` (P7). |
| Chaos | Inject random detector panics/errors; assert scan completion + Unknowns accounting (P6). |
| Performance regression | Synthetic tree generator + synthetic layered image; assert throughput floors and an **RSS ceiling independent of input size** (P2); cached-rescan ≥10× floor. |
| Accuracy oracle | `//go:build oracle` CGO tree-sitter harness tracks precision/recall of the lexer+regex core vs real ASTs — the measured trigger for the WASM AST layer. |
| Concurrency | Full suite under `-race`. |

Profiling is a product feature: `--pprof`, `--trace` (per-phase regions), `--stats` embeds
ScanStats (files walked/skipped, bytes read vs bytes in tree, cache hit rates, per-detector
ns + invocations) into the Inventory — maintainers triage detector #217 with data, and
"what did the scanner skip" is answerable (no silent caps).

## 15. Decision log

| # | Decision | Options considered | Pick | Why (short) |
|---|----------|--------------------|------|-------------|
| D1 | AST strategy | CGO tree-sitter / wazero-WASM tree-sitter / pure-Go lexers+regex / pure-Go tree-sitter runtimes | **Pure-Go region lexers + AC-gated regex; `go/parser` for Go; WASM slot reserved; CGO = dev oracle only** | CGO kills the static-binary distribution story (goreleaser matrix, `go install`, musl). Extraction targets are regular once regions are classified. Decision to ship the WASM layer is gated on measured oracle precision/recall, not speculation. |
| D2 | Rules: declarative vs code | all-Go / all-YAML / hybrid | **Hybrid with the bright line: "keywords + regex over regions + templated claim = YAML; loop/parser/cross-file = Go"** | Model IDs churn weekly — must be a rules PR, never a release. Binary headers and cross-file logic are not expressible as patterns. Mandatory keywords (lint-enforced) + compile-once + ruleset hash in cache keys. |
| D3 | Rule pack layout | per-category monoliths / per-provider files | **One file per provider** | Merge-conflict avoidance and CODEOWNERS routing at hundreds of contributors. |
| D4 | Registration | `init()` self-registration / explicit catalog | **Explicit catalog in composition root; generated built-in list; compiled matcher via constructor** | Deterministic for embedders/tests; rule detectors need compiled state without globals; generated list = no hand-edited conflict hotspot; duplicate IDs panic at startup. |
| D5 | Public API surface | types-only / full 6-package SDK / middle | **`pkg/airom` (domain) + `detect` + `purl` + `detectortest`; v0.x + apidiff CI; rules schema internal until stable** | The plugin SDK is the ecosystem bet and must be public (incl. the contract harness); Syft's rename pain says don't freeze what hasn't survived third-party use. |
| D6 | Concurrency topology | per-(file,detector) goroutines / per-file workers | **Single producer → bounded chan → file workers (detectors sequential per file) → single collector; hard barrier; flat phase-2 pool; clamped byte-semaphore** | Enables read-once with zero buffer synchronization; deadlock-proof channel ownership; `min(size,budget)` clamp kills the 40 GB-file deadlock; no post-detector DAG scheduler (core-churn magnet — rejected). |
| D7 | Identity | purl-first / (Kind,Name,Version,Provider) tuple / CanonicalKey | **CanonicalKey with Class ≠ Kind + content-hash discriminator; purl derived, never root** | Kind-in-key mints embedding/model twins; purl-first splits brains between purl-ful and purl-less detectors; weights identity = bytes. |
| D8 | Confidence | max / flat noisy-OR / grouped noisy-OR | **Per-detector max + capped repetition term → per-method noisy-OR → 0.99 clamp (1.0 = hash/attestation only)** | Flat noisy-OR launders 50 identical hits into fake certainty; max ignores corroboration. |
| D9 | purl for hosted models | mint `pkg:generic/openai/gpt-4.1` / no purl | **No purl; bom-ref + `airom:model.*` properties** | `pkg:generic` is spec-reserved for bare files; fabricated purls pollute Dependency-Track. |
| D10 | Cache | none / blob-only / two-tier + blob | **Two-tier per-file (stat-key, content-key) + per-layer blob, under a self-invalidating namespace hash; findings only, never inventories; try-lock or degrade** | Everyday CI hot path is "one file changed"; namespace hash structurally eliminates forgotten-version-bump staleness; never hang on bbolt's lock. |
| D11 | Image semantics | per-layer walk + merge / squashed stream | **Squashed stream v1; `Location.Layer` recorded when free; stereoscope attribution = v2** | AIBOM answers "what's in the final image"; squashing enables pure streaming. |
| D12 | AI-config attachment | standalone components / global props / bound | **Rule-local `capture_params` (call-site precision) layered over phase-2 proximity binder; refusal over guessing; BoundParam carries provenance** | "temperature=0.2 at src/rag.py:88 on the same call as model=gpt-4.1" survives every writer; ambiguous bindings never fabricate edges. |
| D13 | Manifest parsers | import a parser library / vendor / hand-roll | **Hand-roll easy (JSON/TOML/XML, `x/mod` for go.mod); vendor established yarn/pom/gradle-lock parsers (Apache-2.0, attributed)** | A full parser-library import drags its MVS graph; AIROM needs presence+version, not resolution. |
| D14 | Git strategy | go-git always / exec always | **exec-git fast path, go-git v6 fallback** | go-git shallow-clone inefficiency is documented; established scanners shell out too. |
| D15 | CLI stack | cobra+viper / cobra+koanf / urfave | **cobra + koanf + slog** | Familiar scanner-CLI UX; viper's globals rejected. |
| D16 | Output libs | hand-rolled / libraries | **cyclonedx-go (1.6 ML types confirmed) + go-sarif/v3** | Hand-rolling a conformant modelCard is wasted risk. |
| D17 | Exit codes | findings ⇒ nonzero / always 0 | **0 on successful scan; `--exit-code`/`--fail-on` opt-in** | The single most important CI ergonomic in SBOM scanners. |
| D18 | Lines/columns | 0-based / 1-based | **1-based lines, UTF-16 columns (SARIF rules); 0 = unknown/whole-file** | SARIF is the strictest consumer; one convention, documented translations. |

## 16. Explicitly deferred to v2 (reserved slots, zero model changes required)

1. **SPDX 3.0.1 AI-profile writer** — model already graph + tri-state; near-zero ecosystem
   ingestion today. One new package later.
2. **Attestation verification** (Sigstore / SLSA / in-toto) — `AttestationRef` +
   `MethodAttestation` + `Verified TriState` exist now; v1 records discovered attestation
   files, v2 verifies (the only non-hash path to confidence 1.0).
3. **Per-layer attribution** ("model added in layer N") — `Location.Layer` exists; graduate
   to stereoscope when users ask.
4. **wazero-WASM tree-sitter precision layer** — behind the existing `FileDetector` seam;
   gated on the oracle scoreboard.
5. **Remote/OCI rule registry** — needs signing + trust policy; pairs with attestation work.
6. **Server mode, shared remote cache, SBOM ingestion/merge, Dependency-Track push, VEX** —
   all consumers of the frozen native format; the cache API is already remote-shaped.
7. **Out-of-process plugins** — YAML packs absorb the "add a provider" long tail; don't
   freeze a protocol before the in-proc API survives third-party use.
8. **Git-history scanning, VM images, runtime probing** (querying a live Ollama) — each is a
   new Source or engine mode the abstractions already admit; runtime probing changes the
   trust model and needs its own review.

## 17. Detection coverage map (requirement → mechanism)

| Requirement | Mechanism |
|-------------|-----------|
| OpenAI / Anthropic / Gemini / Bedrock / Azure OpenAI / Cohere / Mistral / Groq / Ollama models | `rules/models/*.yaml` (model-ID literals, SDK call sites) |
| `AutoModel.from_pretrained`, `pipeline(...)` | `rules/models/huggingface.yaml` |
| GGUF / safetensors / ONNX / Torch / SavedModel / TensorRT / TFLite / HDF5 files | `internal/detectors/modelfile` — magic bytes + header metadata (arch, param count, quantization) |
| HF model directories, PEFT adapters | phase-2 `hfdir` + `adapterlink` (config.json, model_index.json, adapter_config.json → DERIVED_FROM) |
| Embedding models (OpenAI, sentence-transformers, bge/e5/MiniLM, Voyage, Cohere, Instructor) | `rules/embeddings/*.yaml`; identity class `hosted-model` collides with generic rules correctly |
| Frameworks (LangChain, LlamaIndex, Haystack, DSPy, CrewAI, AutoGen, SK, SDKs, Transformers, TF, PyTorch, vLLM, ORT, TensorRT, MLflow) | `internal/detectors/manifest` (deps) + `rules/frameworks/*.yaml` (usage) |
| Vector DBs (Chroma, Milvus, Qdrant, Pinecone, Weaviate, FAISS, Redis, Elastic, Atlas, pgvector) | `rules/vectordb/*.yaml` + manifest evidence |
| Prompt assets (files, PromptTemplate, system_prompt) | `internal/detectors/prompt` + `rules/prompts/*.yaml` |
| Datasets (CSV/JSONL/Parquet/Arrow, `load_dataset`, Kaggle, HF) | `internal/detectors/dataset` + `rules/datasets/*.yaml` |
| AI configs (temperature, top_p, top_k, max_tokens, context, seed, stop, reasoning effort, response format) | `capture_params` + `rules/params/*.yaml` + phase-2 `configbind` (§9.5) |
| AI infra (Ollama, vLLM, TGI, Ray Serve, SageMaker, Vertex, Azure ML, Inference Endpoints) | `rules/infra/*.yaml` + `internal/detectors/infra` (Dockerfile/compose/k8s) |
| RAG components (retrievers, rerankers, chunking, knowledge bases) | phase-2 `raglink` stitcher → `rag-pipeline` composite + CONTAINS/QUERIES/EMBEDS_WITH edges |
| Languages: Python, JS, TS, Go, Java, Rust, C#, Kotlin | region lexers (all) + `go/parser` (Go) |
| Scan targets: fs, repo, image, k8s | `internal/source/*` (§7) |
| Outputs: AIBOM JSON, CycloneDX, SARIF, YAML, table | `internal/writer/*` (§11) |
