# airom — Python SDK

Python SDK for [AIROM](https://github.com/Roro1727/airom), the open-source **AI Bill of
Materials (AIBOM) scanner**. Discover AI assets — models, prompts, datasets, embeddings,
vector databases, frameworks, serving infrastructure — across code, containers, and
Kubernetes, and get them back as typed Python objects.

```bash
pip install airom
```

## Quick start

```python
import airom

inv = airom.fs("./my-app", min_confidence=0.8)

for c in inv.by_kind(airom.ComponentKind.HOSTED_LLM):
    print(c.name, c.provider.or_default("-"), c.confidence)
    for occ in c.evidence.occurrences:
        print(f"   {occ.location.path}:{occ.location.line}  [{occ.detector_id}]")
```

```
gpt-4.1 openai 0.87
   src/rag.py:88  [rules/openai/model-literal]
   src/agent.py:12  [rules/openai/sdk-import]
```

Every component carries the evidence that justifies it — that is the point of AIROM, and
the SDK hands you all of it.

## Scanning

```python
airom.scan("./app")                       # auto-detect: path, git URL, or image ref
airom.fs("./app")                         # a directory tree
airom.repo("https://github.com/o/r")      # remote (shallow clone) or a local worktree
airom.image(input="img.tar")              # docker save -o img.tar <ref>
airom.k8s(manifests="./deploy")           # offline: enumerate workload images
airom.version()                           # the underlying binary's ToolInfo
```

Common keyword args mirror the CLI flags: `select`, `rules`, `ignore`, `min_confidence`,
`max_file_size`, `io_budget`, `parallel`, `no_cache`, `cache_dir`, `offline`, `stats`,
plus `binary`, `timeout`, and `cwd`. `None` leaves the tool's own default in place — the
SDK never invents defaults.

`min_confidence=0.8` is the practical high-signal filter: on general-purpose directories,
extension-only dataset detection and keyword-only generation-param detection emit
low-confidence (0.5–0.6) noise. Note the application root always survives the filter — it
is the scan target, not a finding.

`select` tokens are **detector IDs or tags**, not languages — `"-dataset/file"`, not
`"python"`. Run `airom detectors list` (or `airom.raw(["detectors", "list"])`) to see them.

> **Not wired yet:** pulling an image from a live registry/daemon, and live-cluster
> Kubernetes scanning. Both fail with a clear error. Use `image(input=...)` / an OCI
> layout and `k8s(manifests=...)` today.

## Tri-state fields

`version`, `provider`, `download_location` and `release_time` are **tri-state**, and the
SDK preserves the distinction rather than collapsing it into `None`:

| JSON | Meaning | `Opt` |
|---|---|---|
| key omitted | does not apply | `Presence.ABSENT` |
| `null` | applies, but undetermined (SPDX NOASSERTION) | `Presence.UNKNOWN` |
| a value | known | `Presence.KNOWN` |

```python
c.version.known           # bool — only True when a real value is present
c.version.or_none()       # value, or None (collapses absent and unknown)
c.version.or_default("-") # value, or your fallback
c.version.presence        # the full distinction, when you need it
```

## Navigating the graph

```python
inv.components                  # sorted, deterministic
inv.by_kind("vector-db", "framework")
inv.get("airom:1f3a9b2c4d5e6f70")
inv.application                 # the scan-root component
inv.edges_from(c.id)            # typed, evidenced relationships
inv.unknowns                    # "looked relevant, could not process" — honesty channel
inv.stats.files_walked          # requires stats=True
len(inv); [c for c in inv]      # Inventory is sized and iterable
```

## CI gating

A `fail_on` match is a **verdict, not an error** — the scan succeeded and the AIBOM is
complete, so it is reported rather than raised:

```python
res = airom.execute(
    ["fs", "./app"],
    options=airom.ScanOptions(fail_on="hosted-llm&confidence>=0.9", exit_code=7),
)
if res.policy_matched:
    raise SystemExit(res.exit_code)
```

Often you don't need `fail_on` at all — you have the whole graph, so gate in Python:

```python
risky = [c for c in inv if c.model and c.model.pickle_risk]
if risky:
    raise SystemExit(f"unsafe pickle globals in: {[c.name for c in risky]}")
```

## Errors

| Exception | Raised when |
|---|---|
| `BinaryNotFoundError` | the `airom` executable could not be located |
| `ScanError` | a fatal scan failure (exit 2): unreadable target, clone failure, bad flags |
| `OutputError` | no parseable AIBOM, or an unsupported `schemaVersion` |

Detector errors are **not** exceptions: they degrade to `inv.unknowns` records and the
scan still succeeds. That is AIROM's degrade-by-default contract, and the SDK preserves it.

## The binary

The SDK shells out to the `airom` binary and decodes its native JSON — the lossless
superset every other format (CycloneDX, SARIF, YAML, table) projects from. Resolution
order:

1. the `binary=` argument
2. a copy bundled in the wheel (`airom/_bin/airom`)
3. `$AIROM_BINARY`
4. `airom` on `PATH`

Platform wheels bundle the binary, so `pip install airom` is self-contained. Installing
from an sdist does not — put `airom` on your `PATH`
(`go install github.com/Roro1727/airom/cmd/airom@latest`) or set `$AIROM_BINARY`.

## Development

```bash
cd sdk/python
pip install -e ".[dev]"
pytest            # builds the binary from the checkout and tests against it
mypy && ruff check .
```

The suite runs against the **real binary**, not mocks: a wrapper tested only against mocks
proves nothing about the contract it wraps.

Building a wheel needs the Go toolchain (the build hook compiles the binary with
`CGO_ENABLED=0`). Set `AIROM_SKIP_BUNDLE=1` for a pure-Python wheel.

## License

Apache-2.0, same as AIROM.
