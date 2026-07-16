# AIROM CLI Reference

> **Status: implemented as of Phase 4** — the full command surface, config layering, the
> exit-code contract, and the `--fail-on` grammar ([ARCHITECTURE.md §12](./ARCHITECTURE.md#12-cli),
> decisions D15/D17). `scan <dir>` and `fs` run **real scans** (walking, classification,
> read-once pipeline); detectors land in Phase 5 and output writers in Phase 7, so scans
> currently report honest counters. `repo`, `image`, and `k8s` fail fast with a clear error
> until their sources land (Phase 6). `--cache-dir`/`--no-cache` are accepted but inert
> until `internal/cache` lands. The `detectors` group is live as of Phase 5 (the framework
> exists); user rule packs run today via `--rules`. The `rules` and `dev` command groups
> ship with the embedded packs and scaffold templates (Phase 6) — no dead commands before
> the thing they operate on exists.

Stack: cobra (command tree) + koanf (configuration) + stdlib `slog` (logging). One static
binary, `CGO_ENABLED=0`, no daemon, no network unless the target requires it.

## Command tree

```
airom
├── scan <target>          # scheme auto-detect: dir | git URL | image ref (Syft-style)
├── fs <path>              # explicit nouns (Trivy-style)
├── repo <url|path>
├── image <ref>            # --input tar, --platform; remote→daemon→tarball→layout chain
├── k8s [context]          # --namespace | -A; --manifests <dir> (offline mode)
├── detectors {list|explain <id>}     # the explainability view
├── rules {list|lint <file>|test <file>}
├── dev {new-rulepack <name>|new-detector <name>}   # contributor scaffolding
├── clean                  # cache maintenance
└── version
```

## Exit-code contract

> ### ⚠ Read this before wiring AIROM into CI
>
> | Code | Meaning |
> |------|---------|
> | **0** | Scan completed. **Findings are NOT failures.** A scan that discovers 40 AI components and 12 Unknowns still exits 0. |
> | **N** (`--exit-code`, default 1) | Opt-in CI policy: `--fail-on` matched at least one component. Never returned unless you asked for it. |
> | **2** | Fatal error: source acquisition failed (unreadable path, clone failure, image pull failure), invalid flags, or invalid configuration. |
>
> Everything downstream of source acquisition **degrades instead of failing** (invariant
> P6): detector errors, panics, unreadable files, and corrupt headers become first-class
> `Unknown` records in the output and never change the exit code. If you want "fail the
> build when an AI model shows up," that is exactly what `--exit-code`/`--fail-on` are for
> — say it explicitly. (Trivy and Grype both field recurring confusion here; AIROM
> documents it loudly instead.)

## Global flags

Every scan command accepts these. `<size>` values take `k`/`m`/`g` suffixes.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output fmt[=path]` | string, repeatable | `table` | Output format with optional file destination. Formats: `table`, `json` (native airom-json), `cyclonedx`, `sarif`, `yaml`. No `=path` writes to stdout. Repeat for multi-output in one scan. |
| `--format <fmt>` | string | — | Single-format alias for `-o` (Trivy-familiar spelling). |
| `--select <expr>` | string | per-source defaults | Detector selection expression (Syft-style tags + include/exclude): `"python,+modelfile/gguf,-dataset"`. Which expression enabled which detector is recorded in the output `Stats`. |
| `--rules <file>` | string, repeatable | — | Overlay rule pack(s), merged by rule ID (add/override/disable — see [rule-schema.md](./rule-schema.md#the-three-rule-layers-and-merge-semantics)). Changes the effective ruleset hash and therefore the cache namespace. |
| `--parallel N` | int | `GOMAXPROCS` | Worker count. Output is byte-identical at any value (invariant P7 — CI diffs `--parallel 1` vs `16`). |
| `--io-budget <size>` | size | `256m` | Byte-weighted I/O semaphore budget, independent of CPU parallelism (§8). Peak memory is a function of this and the caps below — never of input size. |
| `--max-file-size <size>` | size | `1m` | Full-content read cap for text-category detectors. Header-only binary parsers (GGUF, safetensors, …) are exempt — a 40 GB model file still costs only a 32 KB header read. |
| `--min-confidence <f>` | float | `0` | Presentation-layer filter on assembled confidence (0–1). Merging keeps everything; this only trims output. |
| `--ignore <glob>` | string, repeatable | — | Additional ignore globs, applied on top of `.gitignore`/`.airomignore`. Participates in the cache namespace. |
| `--cache-dir <path>` | path | `<user cache dir>/airom` | bbolt cache location (per-user OS cache directory by default). |
| `--no-cache` | bool | `false` | Disable cache reads and writes for this run. |
| `--cdx-version <v>` | string | `1.6` | CycloneDX spec version: `1.6` (default) or `1.7` (modelCard shape is identical in both). |
| `--sarif-strict-kinds` | bool | `false` | Emit spec-pure `kind:"informational"` instead of the GitHub-Code-Scanning-compatible default `level:"note"`. |
| `--exit-code N` | int | `1` (when policy active) | Exit status to return when `--fail-on` matches. Setting `--exit-code` without `--fail-on` implies failing on **any** component. An explicit `--exit-code 0` with `--fail-on` means "evaluate and report matches, but never fail the build". |
| `--fail-on <expr>` | string | — | CI policy expression evaluated over the assembled inventory. Grammar (finalized in Phase 3): OR-of-AND clauses — `expr = clause *("\|" clause)`, `clause = term *("&" term)`; a term is a kind/tag identifier (`hosted-llm`, `pickle-risk`) or `confidence OP n` with OP ∈ `>= <= > < =` and n ∈ [0,1]. `&` binds tighter than `\|`. Examples: `"hosted-llm"`, `"hosted-llm&confidence>=0.9"`, `"local-model-file\|hosted-llm&confidence>=0.8"`. Identifier terms are validated against the kind/tag vocabulary when the domain model lands (Phase 5). |
| `--offline` | bool | `false` | Assert no network access for the entire run; any operation that would touch the network fails fast instead. (`fs`, local `repo`, and `image --input` scans perform no network access regardless.) |
| `--pprof[=addr]` | string | disabled | Serve `net/http/pprof`; bare flag binds `localhost:6060`. A custom address must be attached with `=` (`--pprof=localhost:7070`) — the space-separated form is rejected with a pointer to this rule. |
| `--trace <file>` | path | — | Write a Go execution trace with per-phase regions (walk / detect / phase-2 / assemble / write). |
| `--stats` | bool | `false` | Emit the full `ScanStats` block (files walked/skipped, bytes read vs bytes in tree, cache hit rates, per-detector timings, selection explanation). Always collected; this controls emission. |
| `-v` / `-q` | count / bool | — | Verbose (repeatable; also expands file:line evidence lists in `table` output) / quiet (errors only). |

## Configuration

Precedence, highest first — implemented with koanf, no global state:

```
flags  >  AIROM_* environment variables  >  .airom.yaml  >  built-in defaults
```

- **Environment:** `AIROM_` + the flag name upper-snake-cased: `AIROM_PARALLEL=4`,
  `AIROM_NO_CACHE=true`, `AIROM_IO_BUDGET=512m`, `AIROM_CACHE_DIR=/var/cache/airom`.
  List-valued settings take comma separation: `AIROM_OUTPUT="table,sarif=airom.sarif"`.
- **File:** `.airom.yaml`, discovered in the working directory. Keys mirror flag names:

```yaml
# .airom.yaml
output:
  - table
  - cyclonedx=aibom.cdx.json
select: "python,typescript,+modelfile/gguf"
parallel: 8
io-budget: 256m
min-confidence: 0.6
ignore:
  - "**/test-fixtures/**"
  - "**/*.example.py"
```

## `.airomignore`

Gitignore syntax, same nested per-directory semantics as `.gitignore`, applied **in
addition to** `.gitignore` (both are honored on `fs`/`repo` scans; `!` re-inclusion works).
Use it for AIROM-specific exclusions you don't want in `.gitignore` — vendored fixtures,
sample prompts, data directories.

Always-on default skips: `.git`, `node_modules`, `vendor`, virtualenvs. These are enforced
in an isolated rule layer that no `!` re-inclusion can override. Ignored files are never
opened (they're excluded at walk time, and the phase-2 resolver enforces the same rules),
and the effective ignore configuration participates in the cache namespace, so changing it
never serves stale results.

On macOS and Windows, ignore matching folds case (mirroring git's default
`core.ignorecase=true` on those platforms).

Limitation: POSIX character classes (e.g. `[[:digit:]]`) are not supported in ignore
patterns — the underlying matcher treats them as literal bracket sets. Use explicit ranges
like `[0-9]` instead.

---

## Commands

### `airom scan <target>`

Scheme auto-detection (Syft-style), tried in order:

1. Existing local path → filesystem scan (`fs`).
2. Git URL (`https://…​.git`, `git@…`, `ssh://…`) → shallow clone → scan (`repo`).
3. Otherwise → image reference (`image`).

Explicit scheme prefixes force interpretation and end all ambiguity: `dir:`, `repo:`,
`image:`.

```console
$ airom scan .
$ airom scan https://github.com/acme/rag-service.git
$ airom scan ghcr.io/acme/inference:v3
$ airom scan image:ubuntu:24.04        # forced: don't try it as a path
```

### `airom fs <path>`

Scan a directory tree. Ignore-aware walking, bounded memory on any tree size. The two-tier
cache (a re-scan where one file changed re-reads one file) lands with `internal/cache`;
until then every scan is cold.

```console
$ airom fs . -o table -o cyclonedx=aibom.cdx.json
$ airom fs /srv/models --select "+modelfile/gguf,-dataset" --stats
$ airom fs . --min-confidence 0.6 -q
```

### `airom repo <url|path>`

Remote URL: `git clone --depth=1 --single-branch --no-tags` into a temp dir (exec-git fast
path, go-git fallback), scan, clean up. Local path: scanned as a plain filesystem; git
metadata (remote, commit, dirty state) feeds output provenance either way.

```console
$ airom repo https://github.com/acme/rag-service.git -o sarif=airom.sarif
$ airom repo ~/src/rag-service
```

### `airom image <ref>`

Resolution chain: remote registry → local daemon → tarball → OCI layout. The squashed
filesystem is streamed **once**; a 40 GB in-image GGUF costs a 32 KB header parse plus a
hashing discard-copy — no memory growth, no temp weights on disk (§7).

| Flag | Description |
|------|-------------|
| `--input <tar>` | Scan a saved image tarball (`docker save` / OCI archive) instead of resolving `<ref>`. No network. |
| `--platform <os/arch>` | Select a platform from a multi-arch index (e.g. `linux/arm64`). |

```console
$ airom image ghcr.io/acme/inference:v3 -o cyclonedx=image-aibom.json
$ airom image --input build/oci-image.tar --offline
$ airom image nvcr.io/nvidia/tritonserver:26.03-py3 --platform linux/amd64
```

### `airom k8s [context]`

Enumerates workloads (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, bare Pods —
paginated, deduped by ownerRefs), extracts every container image (including init and
ephemeral containers), dedupes refs, and scans each unique image. Uses the current
kubeconfig context unless one is named.

| Flag | Description |
|------|-------------|
| `--namespace <ns>` | Restrict to one namespace. |
| `-A` | All namespaces. |
| `--manifests <dir>` | **Offline mode**: extract image refs from manifest YAML / rendered Helm output instead of a live cluster. |
| `--parallel-images` | Scan images concurrently (serial by default — image scans are already internally parallel). |

```console
$ airom k8s --namespace ml-serving -o table
$ airom k8s prod -A -o cyclonedx=cluster-aibom.json
$ airom k8s --manifests ./deploy/rendered --offline
```

### `airom detectors {list | explain <id>}`

Capability-as-data: every detector's ID, version, tags, and exactly what it looks at —
the scanner is self-documenting. `list` shows the effective set for a hypothetical scan
(honors `--select`); `explain` prints one detector's full selector, needs, and claims.

```console
$ airom detectors list --select "python,-dataset"
$ airom detectors explain modelfile/gguf
```

Illustrative `explain` output (final layout may differ):

```
id:        modelfile/gguf
version:   3
type:      code (FileDetector, phase 1)
selects:   ext .gguf · magic "GGUF" @0 · need: header · max-size: unlimited
emits:     local-model-file (ModelFacet: architecture, param-count, quantization, context-length)
method:    binary-analysis
```

### `airom rules {list | lint <file> | test <file>}`

- `list` — the effective compiled ruleset (embedded + `--rules` overlays), each rule with
  its originating layer.
- `lint <file>` — the full validation contract from
  [rule-schema.md](./rule-schema.md#lint-contract): regexes compile, keywords mandatory,
  named groups referenced, IDs globally unique, fixture coverage.
- `test <file>` — run a pack's fixtures and compare against its golden **without a Go
  toolchain** — the rules-contributor loop in one command.

```console
$ airom rules lint rules/models/fireworks.yaml
$ airom rules test rules/models/fireworks.yaml
$ airom rules list --rules ./mycorp-overrides.yaml
```

### `airom dev {new-rulepack <name> | new-detector <name>}`

Contributor scaffolding: `new-rulepack` creates a pack skeleton plus fixture files under
`rules/models/` (category selectable via `--category`); `new-detector` creates a Go
detector package skeleton with a `detectortest` harness test. Both are walked end-to-end in
[plugin-guide.md](./plugin-guide.md). The command group ships together with its scaffold
templates in Phase 6.

### `airom clean`

Cache maintenance: removes the scan cache (all namespaces) under `--cache-dir`. The escape
hatch when you want a guaranteed cold scan — though note the cache namespace already
self-invalidates on any change to detectors, rules, size caps, or ignore config (§10).

Safety: `clean` only removes directories the tool itself creates — the basename must be
`airom` (the default cache location) or `airom-cache` (the temp fallback) — and refuses
`$HOME` and the volume root by filesystem identity (immune to case-insensitive paths and
symlinks). Anything else must be deleted manually.

```console
$ airom clean
$ airom clean --cache-dir /var/cache/airom
```

### `airom version`

Tool name, version, commit, and build date — the same `ToolInfo` embedded in every
generated AIBOM.

---

## Recipes

**Terminal summary + BOM file + Code Scanning upload, one pass:**

```console
$ airom scan . -o table -o cyclonedx=aibom.cdx.json -o sarif=airom.sarif
```

**CI gate — fail the build only on high-confidence hosted LLM usage:**

```console
$ airom fs . --fail-on "hosted-llm&confidence>=0.9" --exit-code 1 -o table
```

**Air-gapped image scan from a build artifact:**

```console
$ airom image --input dist/app-image.tar --offline -o json=aibom.json
```

**Try an unmerged rule pack against your codebase:**

```console
$ airom scan . --rules ./fireworks.yaml --select "+rules/fireworks"
```

**Profile a slow scan:**

```console
$ airom fs /big/monorepo --stats --trace scan.trace --pprof
```
