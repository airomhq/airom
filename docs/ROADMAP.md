# AIROM Roadmap

> **Current status (mid-2026):** `v0.1.0-dev`, pre-release, unpublished. Phase 1
> (architecture) is accepted; Phase 2 (repository structure) is in progress. The canonical
> design this roadmap builds is [ARCHITECTURE.md](./ARCHITECTURE.md); scope boundaries come
> from its §15 decision log and §16 deferral list, and this document does not re-litigate
> them.

## v0.1.0: the ten-phase build-out

v0.1.0 is the first shippable release: scan a filesystem, repository, container image, or
Kubernetes workload set and emit an evidence-first AIBOM in five formats, from one static
binary. It is built in ten phases, in order; each phase has an exit criterion, and later
phases' docs (this one included) are written against the committed design rather than the
current state of the code.

| # | Phase | Delivers | Done when |
|---|-------|----------|-----------|
| 1 | **Architecture** | The canonical design: layout, domain model, detector framework, concurrency topology, assembly calculus, writer set, decision log (§15). | Adversarial review complete; decisions recorded with losing alternatives. **✔ Accepted.** |
| 2 | **Repository structure** | Go module scaffold on the §4 layout: `cmd/`, `pkg/airom/{,detect,purl,detectortest}`, `internal/*`, `rules/*`, `schemas/`, `docs/`, `testdata/`; lint-enforced import rules (`internal` → `pkg` only, `pkg/airom` stdlib-only); license, module hygiene. | `go build ./...` and `go vet ./...` green; layout lint passes; every package has a doc comment stating its contract. |
| 3 | **CLI** | The full [cli.md](./cli.md) surface: cobra command tree, koanf config precedence (flags > `AIROM_*` env > `.airom.yaml` > defaults), `.airomignore` plumbing, exit-code contract, multi-output flag parsing, `detectors`/`rules`/`dev` command frames. | CLI behaviors script-tested against `docs/cli.md`; exit-code contract covered by tests. |
| 4 | **Filesystem scanner** | The streaming engine of §8: single-producer walker, bounded channels, worker pool, single collector, hard phase barrier; `filectx` read-once contract; `dispatch` selector index; `classify`; `xio` (pooled buffers, spool, clamped byte-semaphore); `dirsource` with the nested-ignore stack, and `gitsource` delegating to it. | Bounded-memory (RSS ceiling) and `--parallel 1` vs `16` determinism tests pass on fixture trees; permission errors degrade to Unknowns. |
| 5 | **Plugin framework** | The public SDK: `pkg/airom` domain model, `pkg/airom/detect` interfaces, `purl` helpers, the `detectortest` harness (dir- and tar-stream-backed); the rule engine, meaning the YAML compiler, the lint contract of [rule-schema.md](./rule-schema.md), the Aho–Corasick prefilter, and the per-language region lexers; cache with the self-invalidating namespace key; `all/` registration generator. | A sample detector passes `detectortest.Run` under both backings; `rules lint` enforces the full contract; cache namespace changes on any rule/detector/caps/ignore change. |
| 6 | **Detectors** | Built-in code detectors (`modelfile` header parsers, `manifest`, `gosrc`, `prompt`, `dataset`, `infra`, phase-2 `project` set) and the embedded rule packs across all eight categories; `imagesource` and `k8ssource` land here behind the Phase 4 `Source` seam (spool policy, tee-hash-during-discard, offline manifest mode); `dev` scaffold templates. | Every row of the §17 coverage map has at least one passing fixture; rule packs each carry ≥1 positive + ≥1 negative fixture. |
| 7 | **Writers** | The five writers (airom-json, CycloneDX 1.6/1.7, SARIF 2.1.0, YAML, table) as pure `*Inventory → []byte` projections; `schemas/airom-v1.schema.json`; `docs/mapping.md` master field-mapping table. | Native/CDX/SARIF outputs validate against their official schemas in CI; mapping round-trip test green. |
| 8 | **Tests** | The full §14 matrix: golden E2E fixture repos (including the OCI layout built in CI and `k8s-manifests/`), fuzz corpora for every binary parser, chaos (injected panics → Unknowns), assembler property tests, performance regression with an input-size-independent RSS ceiling, the CGO tree-sitter accuracy-oracle job, everything under `-race`. | CI matrix green; oracle scoreboard producing precision/recall numbers. |
| 9 | **Workflows** | CI pipelines and release engineering: build matrix (`CGO_ENABLED=0`), goreleaser, reproducible builds, cosign signing, a self-scan gate on the release binary, apidiff gate on `pkg/airom`, "detector diff ⇒ version bump" check, CODEOWNERS routing for `rules/`. | A tagged release candidate produces signed, reproducible artifacts end to end. |
| 10 | **Review** | Adversarial architecture-conformance review of the implementation against ARCHITECTURE.md; apidiff baseline freeze for the v0.x SDK; docs pass; cut `v0.1.0`. | Every §2 invariant demonstrably CI-enforced; no known divergence between docs and behavior. |

**Scope note on sources.** Phase 4 is named for the filesystem scanner because `dirsource`
is the first `Source` implementation and the engine's proving ground, but the `Source`
interface is shaped by the *worst* source (the non-seekable squashed OCI tar stream, §7)
from day one. `imagesource` and `k8ssource` are inside v0.1.0 scope: they land in Phase 6
behind the unchanged seam, and Phase 8's golden E2E matrix (OCI layout, k8s manifests)
gates the release on them.

## v0.2 and beyond: reserved slots, zero model changes

Everything below is **explicitly deferred, not undecided**. The list is §16 of the
architecture, and the framing is the point: each item has a *reserved slot*, meaning the
v0.1.0 domain model, interfaces, or cache API already contain the seam it plugs into.
Landing any of them requires **zero changes to the core model**, and that asymmetry is a
standing acceptance test of the architecture. If one of these turns out to need core
surgery, that's an architecture bug to review, not a normal feature cost.

1. **SPDX 3.0.1 AI-profile writer.** The model is already an element graph with typed edges
   and tri-state optionals (deterministic `NOASSERTION`); ecosystem ingestion of SPDX 3 AI
   is near-zero today. *Reserved slot:* one new package under `internal/writer`, nothing
   else ([§11](./ARCHITECTURE.md#11-output-writers-internalwriter) names this the
   acceptance test).
2. **Attestation verification** (Sigstore / SLSA / in-toto). v1 already *records*
   discovered attestation files; v2 *verifies* them, the only non-hash path to confidence
   1.0. *Reserved slots:* `AttestationRef`, `MethodAttestation`, and the `Verified`
   tri-state all exist in the v1 model; writers already map them.
3. **Per-layer attribution** ("this model was added in layer N"). *Reserved slot:*
   `Location.Layer` exists and is populated when free; graduate to stereoscope-style layer
   analysis when users ask.
4. **wazero-WASM tree-sitter precision layer.** Sits behind the existing `FileDetector`
   seam; adopted **only** when the CGO tree-sitter accuracy oracle (§14, a dev-time CI job
   that never ships) shows measured precision/recall failures of the lexer+regex core. The
   decision is evidence-driven, not faith-based.
5. **Remote/OCI rule registry**: the third rule layer ([rule-schema.md](./rule-schema.md#the-three-rule-layers-and-merge-semantics)).
   Needs pack signing and a trust policy; pairs with the attestation work. The layered
   merge semantics already reserve its position.
6. **Server mode, shared remote cache, SBOM ingestion/merge, Dependency-Track push, VEX.**
   All are consumers of the frozen native format (`schemaVersion: "1"` from release one);
   the cache API is already remote-shaped (`MissingBlobs`-style interface, §10).
7. **Out-of-process plugins.** YAML rule packs absorb the "add a provider" long tail;
   a wire protocol will not be frozen before the in-process `pkg/airom/detect` API has
   survived real third-party use.
8. **Git-history scanning, VM images, runtime probing** (e.g. querying a live Ollama).
   Each is a new `Source` or engine mode the existing abstractions admit. Runtime probing
   changes the trust model (the scanner would talk to running services) and gets its own
   security review before design.

## Compatibility promises along the way

- **Native output** is a versioned API from release one: `schemaVersion: "1"`, JSON Schema
  published per release under `schemas/`.
- **`pkg/airom/...`** (the plugin SDK) is semver-guarded by apidiff in CI and ships as
  v0.x until the interfaces survive third-party use. Breaking changes are possible but
  deliberate and changelogged, never accidental.
- **Rule pack format**: the contract is [rule-schema.md](./rule-schema.md); the backing Go
  types stay `internal` in v0 and graduate to `pkg/` when stable.
- **A new model ID is a rules PR, never a release.** The fast-moving detection surface
  stays declarative, and users can adopt unmerged packs immediately via `--rules`.
