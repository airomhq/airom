# AIROM CLI Reference

> **Status** — the command surface, config layering, the exit-code contract, and the
> `--fail-on` grammar are implemented ([ARCHITECTURE.md §12](./ARCHITECTURE.md#12-cli),
> decisions D15/D17), as are the full detector set, the 49 embedded rule packs (102 rules),
> the five output writers, and the `detectors`/`rules`/`dev` command groups.
>
> Source coverage: `fs` and `repo` are complete (local worktrees, plus remote clone via an
> installed `git`). `image` scans docker-save/OCI archives and OCI layouts. `k8s --manifests`
> enumerates workload images from manifest YAML or rendered Helm output.
>
> **Not implemented yet**, and the affected flags say so in their own `--help`:
>
> - **Caching** (`internal/cache`) — every scan is cold. `--no-cache` is a no-op;
>   `--cache-dir` is used only by `airom clean`.
> - **Live registry/daemon image pulls** — `airom image <ref>` fails with a clear error;
>   use `--input <archive>`. `--platform` therefore has nothing to select from.
> - **Live-cluster scanning** — `airom k8s` without `--manifests` fails with a clear error.
>   `--parallel-images` is a no-op, since manifest mode lists images rather than pulling them.

Stack: cobra (command tree) + koanf (configuration) + stdlib `slog` (logging). One static
binary, `CGO_ENABLED=0`, no daemon, no network unless the target requires it.

## Command tree

```
airom
├── scan <target>          # scheme auto-detect: dir | git URL | image ref (Syft-style)
├── fs <path>              # explicit nouns (scanner-style)
├── repo <url|path>
├── image <ref>            # --input tar, --platform; remote→daemon→tarball→layout chain
├── k8s [context]          # --namespace | -A; --manifests <dir> (offline mode)
├── diff <old> <new>       # semantic delta between two native AIBOMs; --format table|markdown|json
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
> — say it explicitly. (SBOM scanners commonly field recurring confusion here; AIROM
> documents it loudly instead.)

## Global flags

Every scan command accepts these. `<size>` values take `k`/`m`/`g` suffixes.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-o, --output fmt[=path]` | string, repeatable | `table` | Output format with optional file destination. Formats: `table`, `json` (native airom-json), `cyclonedx`, `sarif`, `yaml`, `compliance` (a Markdown report of `--compliance` results — see [compliance.md](./compliance.md)). No `=path` writes to stdout. Repeat for multi-output in one scan. |
| `--format <fmt>` | string | — | Single-format alias for `-o` (familiar scanner spelling). |
| `--select <expr>` | string | per-source defaults | Detector selection expression (Syft-style tags + include/exclude): `"rules,+modelfile/gguf,-dataset/file"`. Which expression enabled which detector is recorded in the output `Stats`. |
| `--rules <file>` | string, repeatable | — | Overlay rule pack(s), merged by rule ID (add/override/disable — see [rule-schema.md](./rule-schema.md#the-three-rule-layers-and-merge-semantics)). Changes the effective ruleset hash and therefore the cache namespace. |
| `--compliance <framework>` | string, repeatable | — | Map the AIBOM onto a governance framework (e.g. `nist-ai-rmf`) and attach the result as CycloneDX `definitions`/`declarations`. A mapping, never a certification — see [compliance.md](./compliance.md). |
| `--no-eol` | bool | `false` | Disable the **hosted-model end-of-life overlay**, which is **on by default** (its catalog comes from a fetched bundle when one carries it, else the embedded copy — see [eol.md](./eol.md)). It matches the AI models AIROM inventoried against a curated catalog of provider retirement announcements and attaches a dated, sourced lifecycle (`supported` / `deprecated` / `retired`) with the migration target the provider names. Unlike `--cve` the catalog is local (bundle or embedded), never a live query, so it needs no network and keeps working under `--offline`. A model the catalog does not cover carries no claim at all — "unknown" is the absence of a statement, never a quiet "supported". |
| `--include-tests` | bool | `false` | Count AI found **only** in test scaffolding — `testdata/`, `*_test.go`, `tests/`, `spec/`, `__tests__/`, `test_*.py`, `*.spec.ts`, and friends, matched against paths **relative to the scan root**. Off by default: an AIBOM answers "what AI does this software use?", and a rule-pack fixture is not an answer. Such components are still detected and still present in the native JSON (`testOnly: true`) and in CycloneDX (`scope: "excluded"`); the flag decides whether the **table, SARIF, and `--fail-on`** count them. A component reached from production code is never scoped out, even if tests reach it too. The table always states how many it withheld. |
| `--no-cve` | bool | `false` | Disable the **CVE overlay**, which is **on by default**. The overlay matches the AI package dependencies AIROM inventoried (by their purl) against the live [OSV.dev](https://osv.dev) advisory database and attaches the resulting CVEs — see [cve.md](./cve.md). Scoped to AI packages, not a general-purpose SCA. Because it queries a live database it is neither offline nor deterministic across time (the same scan surfaces more CVEs as OSV grows), so disable it with `--no-cve` for a byte-stable BOM. `--offline` also disables it. Degrades honestly: a network failure yields no CVEs and a warning, never a fatal error — except that an active `--fail-on cve…` gate fails closed rather than silently pass. (The old `--cve` flag is a deprecated no-op.) |
| `--parallel N` | int | `GOMAXPROCS` | Worker count. Output is byte-identical at any value (invariant P7 — CI diffs `--parallel 1` vs `16`). |
| `--io-budget <size>` | size | `256m` | Byte-weighted I/O semaphore budget, independent of CPU parallelism (§8). Peak memory is a function of this and the caps below — never of input size. |
| `--max-file-size <size>` | size | `1m` | Full-content read cap for text-category detectors. Header-only binary parsers (GGUF, safetensors, …) are exempt — a 40 GB model file still costs only a 32 KB header read. |
| `--min-confidence <f>` | float | `0` | Presentation-layer filter on assembled confidence (0–1). Merging keeps everything; this only trims output. |
| `--ignore <glob>` | string, repeatable | — | Additional ignore globs, applied on top of `.gitignore`/`.airomignore`. Participates in the cache namespace. |
| `--cache-dir <path>` | path | `<user cache dir>/airom` | bbolt cache location (per-user OS cache directory by default). Also where `airom rules update` stores fetched rule bundles. |
| `--no-cache` | bool | `false` | Disable cache reads and writes for this run. |
| `--no-cached-rules` | bool | `false` | Ignore any bundle fetched by `airom rules update` (from [airom-rules](https://github.com/airomhq/airom-rules)); scan with the built-in packs — and the built-in model lifecycle catalog. |
| `--cdx-version <v>` | string | `1.6` | CycloneDX spec version: `1.6` (default) or `1.7` (modelCard shape is identical in both). |
| `--sarif-strict-kinds` | bool | `false` | Emit spec-pure `kind:"informational"` instead of the GitHub-Code-Scanning-compatible default `level:"note"`. |
| `--exit-code N` | int | `1` (when policy active) | Exit status to return when `--fail-on` matches. Setting `--exit-code` without `--fail-on` implies failing on **any** component. An explicit `--exit-code 0` with `--fail-on` means "evaluate and report matches, but never fail the build". |
| `--fail-on <expr>` | string | — | CI policy expression evaluated over the assembled inventory. Grammar (finalized in Phase 3): OR-of-AND clauses — `expr = clause *("\|" clause)`, `clause = term *("&" term)`; a term is a component kind (`hosted-llm`), an artifact-risk selector (`risk`, `risk:high`, `risk:pickle-import` — see [risks.md](./risks.md); `pickle-risk` is a deprecated alias for `risk:pickle-import`), a compliance-gap selector (`compliance:gap`, `compliance:<framework>`, `compliance:<framework>:<control>` — see [compliance.md](./compliance.md); requires `--compliance`, and cannot be `&`-combined), a CVE selector (`cve` for any CVE, or `cve:<severity>` where severity is a **threshold** — `cve:high` fires on high **and** critical — see [cve.md](./cve.md); the overlay is on by default, so this works unless you passed `--no-cve`/`--offline`), a model-lifecycle selector (`eol` for any announced retirement, `eol:retired` / `eol:deprecated` — also a threshold, so `eol:deprecated` fires on retired too — or `eol:before:<YYYY-MM-DD>`, the planning gate: "fail if anything in this stack dies before that date". A model with no catalog record never matches, and an undated deprecation never matches `before:` — neither can answer the question. Requires the overlay, which is on by default and works offline), or `confidence OP n` with OP ∈ `>= <= > < =` and n ∈ [0,1]. `&` binds tighter than `\|`. Examples: `"hosted-llm"`, `"risk:high"`, `"hosted-llm&confidence>=0.9"`, `"local-model-file\|hosted-llm&confidence>=0.8"`. Identifiers are validated at parse time: an unknown term is a usage error, never a silently-passing gate. Detector tags are **not** terms — components record the kind they are, not the detector that found them. |
| `--offline` | bool | `false` | Assert no network access for the entire run; an operation that would touch the network fails fast **before** reaching it, rather than erroring after the fact. In practice the one such operation is cloning a remote `repo` URL — `fs`, local `repo`, `image --input`, and `k8s --manifests` never touch the network, and live registry pulls / live-cluster scanning are not implemented (they fail regardless). |
| `--pprof[=addr]` | string | disabled | Serve `net/http/pprof`; bare flag binds `localhost:6060`. A custom address must be attached with `=` (`--pprof=localhost:7070`) — the space-separated form is rejected with a pointer to this rule. |
| `--trace <file>` | path | — | Write a Go execution trace with per-phase regions (walk / detect / phase-2 / assemble / write). |
| `--stats` | bool | `false` | Emit the full `ScanStats` block (files walked/skipped, bytes read vs bytes in tree, cache hit rates, per-detector timings, selection explanation). Always collected; this controls emission. |
| `--wide` | bool | `false` | Table output only: list every `file:line` occurrence (with the detector that fired) under each component. The default table shows just the primary `LOCATION` and an occurrence count; `--wide` is the terminal equivalent of the JSON `evidence.occurrences[]`. |
| `-v` / `-q` | count / bool | — | Verbose (repeatable; raises log detail — `-vv` adds source locations) / quiet (errors only). |
| `--no-progress` | bool | `false` | Disable the scan progress indicator. It is already auto-disabled when stderr is not a terminal (pipes, redirects, CI) and under `-q`, so this is only for suppressing it on an interactive terminal. Progress renders to **stderr only** — it never touches the AIBOM on stdout. |

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
select: "rules,+modelfile/gguf"
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

It is also the right place for **a tree whose AI names are data rather than
dependencies**: a routing table, a docs page listing supported providers, a
migration script's lookup map. No static analysis can distinguish "we list these
providers because we call them" from "we list them because we catalogue them", so
the judgement belongs with the people who know the answer. AIROM's own repository
ships an [`.airomignore`](https://github.com/airomhq/airom/blob/main/.airomignore)
doing exactly this for its detector pattern tables. (You do **not** need an entry
for AIROM rule packs or lifecycle catalogs — those are recognised structurally and
never inventoried as prompts.)

Always-on default skips: `.git`, `node_modules`, `vendor`, virtualenvs, and **version-stamped dependency directories** (`…/lib@v1.2.3/` — the Go module cache and the pnpm store). That last one keys on the `@v<digit>` stamp, not on `pkg/mod/`, so a project with its own `pkg/mod` package keeps being scanned; point AIROM at a cached module directly and it is reported normally. These are enforced
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
$ airom fs /srv/models --select "+modelfile/gguf,-dataset/file" --stats
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

### `airom diff <old-aibom.json> <new-aibom.json>`

Compare two native AIBOM documents (`airom scan <target> -o json=<file>`) and report the
**semantic delta**: components added, removed, and changed, keyed by the stable component
ID. Version is deliberately not part of component identity (§9.2), so a version bump reads
as a field change on one component — never as a remove+add pair. Evidence churn
(occurrence counts, detector sets) is not compared, and confidence is compared by band, so
two scans of unchanged code diff as empty. The scan root and test-scoped components are
excluded by default (`--include-tests` to count them).

One format to stdout, selected with `--format`:

| Format | For |
|---|---|
| `table` (default) | terminals — summary box + added/removed/changed tables |
| `markdown` | CI — ready to post as a PR comment |
| `json` | tooling — full component snapshots plus field-level changes |

Added and removed components carry their overlays: a **RISK**, **VULN**, or **EOL** column
appears when that section surfaces one, so a PR that introduces a retired model or a
checkpoint that executes code on load says so in the row rather than only in the full scan.
Clean deltas stay narrow — the columns are conditional, exactly as in the scan table.

The gate flags work like scan's, evaluated over the **added and changed** components only:
`--fail-on` names the AI delta you refuse to merge, `--exit-code N` alone fails on any
added or changed component. Removals never trip the gate — a policy names AI you do not
want to appear, and a removal is that policy succeeding. `compliance:` terms are rejected
(they gate a scan's framework mapping, not a delta). Wrong-format input (CycloneDX, SARIF)
is refused explicitly rather than diffed as empty.

**Both documents must come from the same tooling.** A diff attributes its delta to
the code, so `airom diff` compares the `tool` block of the two documents — binary
version, ruleset version and hash, lifecycle catalog — and reports any mismatch as
**⚠ Not comparable** in every format. A rule added between the two scans makes
components appear that the PR never wrote; a rule removed makes them vanish. With
`--fail-on` active a mismatch is a **fatal error (exit 2)**, the same refusal an
unevaluable `eol`/`cve` gate gives: skipping the gate would be a false green and
running it a false red, so the honest answer is "I cannot tell". Without a gate the
diff still prints, carrying the caveat. Scan base and head in one CI run and this
never fires.


```console
$ airom diff old.json new.json
$ airom diff base.json head.json --format markdown > aibom-diff.md
$ airom diff base.json head.json --fail-on "hosted-llm|local-model-file"
$ airom diff base.json head.json --exit-code 1     # any AI change fails the build
```

### `airom detectors {list | explain <id>}`

Capability-as-data: every detector's ID, version, tags, and exactly what it looks at —
the scanner is self-documenting. `list` shows the effective set for a hypothetical scan
(honors `--select`); `explain` prints one detector's full selector, needs, and claims.

```console
$ airom detectors list --select "rules,+modelfile/gguf"
$ airom detectors explain modelfile/gguf
```

`explain` output:

```console
$ airom detectors explain modelfile/gguf
id:        modelfile/gguf
version:   1
phase:     file
selects:   ext:.gguf · magic:1 signature(s)
need:      content
selected:  selected by "default"
```

### `airom rules {list | lint <file> | test <file> | update [version]}`

- `list` — the effective compiled ruleset (embedded + `--rules` overlays), each rule with
  its originating layer.
- `lint <file>` — the full validation contract from
  [rule-schema.md](./rule-schema.md#lint-contract): regexes compile, keywords mandatory,
  named groups referenced, IDs globally unique, fixture coverage.
- `test <file>` — run a pack's fixtures and compare against its golden **without a Go
  toolchain** — the rules-contributor loop in one command. Handed a lifecycle catalog it
  says so and exits 0 (a catalog has no fixtures; `lint` is what validates one), so a
  publishing pipeline can run both commands over every YAML in the bundle.
- `update [version]` — fetch, verify (ed25519), and cache a signed rule bundle from the
  [airom-rules](https://github.com/airomhq/airom-rules) channel; scans then prefer it over
  the embedded packs. The **only** rules subcommand that touches the network — scans never
  do. Flags: `--rules-source <url>` (mirror/testing override), `--insecure-skip-signature`
  (skip signature verification; the checksum is still enforced). `--offline` refuses to
  fetch; `--no-cached-rules` makes a scan ignore the bundle; `airom clean` removes it.

```console
$ airom rules lint rules/models/fireworks.yaml
$ airom rules test rules/models/fireworks.yaml
$ airom rules list --rules ./mycorp-overrides.yaml
$ airom rules update v1.2.0
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

**PR gate — surface and gate the AI delta a pull request introduces:**

```console
$ airom repo https://github.com/acme/rag-service.git -o json=base.json   # base branch
$ airom fs . -o json=head.json                                           # PR checkout
$ airom diff base.json head.json --format markdown > aibom-diff.md       # post as PR comment
$ airom diff base.json head.json --fail-on "hosted-llm|local-model-file"
```

**Air-gapped image scan from a build artifact:**

```console
$ airom image --input dist/app-image.tar --offline -o json=aibom.json
```

**Try an unmerged rule pack against your codebase:**

```console
$ airom scan . --rules ./fireworks.yaml --select "rules"
```

**Profile a slow scan:**

```console
$ airom fs /big/monorepo --stats --trace scan.trace --pprof
```
