# CVE overlay

AIROM's core scan is offline and deterministic: it reports what an artifact
*is*. The **CVE overlay** adds what is *known about it today*. It matches the
AI package dependencies AIROM already inventoried (by their [purl][purl])
against the live [OSV.dev][osv] advisory database and attaches the resulting
CVEs to those components.

It is **on by default**. To turn it off, pass **`--no-cve`** (or **`--offline`**,
which disables it along with every other network operation). Two honest reasons
you might want to:

- **It touches the network.** Every other AIROM operation on a local target is
  offline; this one queries a live API. `--offline` disables it (and asserts no
  network for the whole run).
- **It is not deterministic across time.** The same scan of the same code
  surfaces *more* CVEs next month as OSV grows. That is the right behavior for a
  vulnerability check and the wrong behavior for a reproducible bill of
  materials, so disable it (`--no-cve`) when you need a byte-stable BOM.

> **Scope: AI dependencies, not a general-purpose SCA.** The overlay queries
> only the components AIROM inventories: the AI/ML frameworks, SDKs, and
> serving libraries it already identifies (pypi, npm, golang, cargo, maven,
> nuget purls). It is not, and does not try to be, a full software-composition
> scanner for your entire dependency tree. Use a dedicated SCA for that; use
> this to answer "do the AI parts of my stack have known CVEs?"

## Usage

```console
$ airom fs .                                    # CVEs included by default
$ airom fs . -o cyclonedx=aibom.cdx.json        # CVEs ride in vulnerabilities[]
$ airom fs . --fail-on cve:high --exit-code 1   # fail CI on a high/critical CVE
$ airom fs . --no-cve                           # skip the overlay (offline, byte-stable)
$ airom fs . --offline                          # skip it (and assert no network at all)
$ airom fs . --fix                              # ...and fix them, interactively
$ airom fs . --fix-all                          # ...and fix every one that can be
```

The overlay composes with everything else. `--compliance` frameworks that map
to "known vulnerabilities" see the CVEs (it runs before compliance), and every
output format projects them.

## How CVEs appear in output

| Format | Where |
|--------|-------|
| CycloneDX | top-level `vulnerabilities[]` carrying the CVE `id`, `source.name: osv.dev`, a `ratings[]` entry with `method: CVSSv31`, the real `score`, `severity`, and `vector`, aliases as `references[]`, and `affects[].ref` pointing at the component's `bom-ref`. The first fixed version rides in an `airom:cve.fixedVersion` property. |
| SARIF | a `cve/<id>` rule carrying the GitHub `security-severity` property. That is the **real CVSS base score**, not the synthetic marker the risk rules use. It also carries a result (level `error`/`warning`/`note` by severity) anchored to the manifest line that declared the vulnerable package. |
| Native JSON / YAML | `component.vulnerabilities[]` holding `{id, aliases, severity, score, vector, summary, fixedVersion, source, url}`. |
| Table | a `VULN` column on the component (top severity + count, e.g. `high (2)`), a `Vulnerabilities` breakdown in the summary panel, and a per-CVE detail table below with `LIBRARY / VULNERABILITY / SEVERITY / STATUS / INSTALLED / FIXED / TITLE`, most-severe first. Per-package columns (`LIBRARY`, `INSTALLED`, `FIXED`) merge vertically across a package's CVEs, Trivy-style, so the name and versions show once and span the group. |
| `--fail-on` | `cve` (any CVE), or `cve:<severity>` (a **threshold**; see below). |
| `--fix` / `--fix-all` | an interactive table with a per-package Fix action, or the same plan applied non-interactively. See [Fixing what it finds](#fixing-what-it-finds). |
| `--fix-verify` | a dry-run resolver check that the fixed pins still install together. See [Verifying the fix actually builds](#verifying-the-fix-actually-builds----fix-verify). |

## Fixing what it finds

A scan that only names the problem leaves the work where it started. **`--fix`**
opens an interactive table of the advisories the scan found and rewrites the
manifest pins you choose; **`--fix-all`** applies every fixable one without the
table, for CI and for terminals that cannot host it.

```console
$ airom scan . --fix        # interactive: click [ Fix ] on a row, or press `a` for all
$ airom scan . --fix-all    # non-interactive: apply every fixable pin
$ airom scan . --fix --fix-verify   # ...and confirm the result still resolves
```

```
┌──────────────┬────────────────┬──────────┬───────────┬───────────────┬─────────┐
│ PACKAGE      │ VULNERABILITY  │ SEVERITY │ INSTALLED │ FIX TO        │ ACTION  │
├──────────────┼────────────────┼──────────┼───────────┼───────────────┼─────────┤
│ langchain    │ CVE-2023-36281 │ CRITICAL │ 0.0.310   │ 1.3.9 (major) │ [ Fix ] │
│              │ CVE-2024-0243  │ LOW      │           │               │         │
│ transformers │ CVE-2023-6730  │ CRITICAL │ 4.30.0    │ 5.5.0 (major) │ ✔ fixed │
└──────────────┴────────────────┴──────────┴───────────┴───────────────┴─────────┘
  ↑/↓ move · enter or click [ Fix ] · a fix all · ? help · q quit
```

**Terminal size.** The table needs at least **46 columns and 13 rows**. Below
either it refuses to draw and points at `--fix-all`: a frame larger than the
screen scrolls, and a scrolled frame puts every click on the wrong row.

**Keys and mouse.** `↑`/`↓` (or `j`/`k`, or the wheel) move; `enter`, `space`,
or a click on the `[ Fix ]` cell applies that package's fix; `a` applies every
fixable package; `q` quits. The detail pane under the table shows the advisory
on the selected row and the exact manifest line the button would rewrite, so
the edit is readable before it is made.

**What "fix" means.** One version per package: the **highest** fixed version any
of that package's advisories names, because bumping to the first one leaves the
rest open. Only the version token on the declaring line changes — the comparison
operator, extras, indentation, trailing comment, and the file's line endings all
survive byte-for-byte, so the diff is reviewable.

A bump that leaves the package's compatibility line (npm's caret rule: the major
for `1.0.0`+, the minor while the major is `0`) is marked **`(major)`** in the
table and called out in the detail pane. It is still the remediation — but it is
also an API break, and AIROM says so rather than trading a disclosed
vulnerability for an undisclosed build failure.

Clearing the advisory is not the same as the project still building — add
[`--fix-verify`](#verifying-the-fix-actually-builds----fix-verify) to check.

**What it will not touch.**

- **Lockfiles, installed metadata, and frozen binaries.** A lockfile records a
  resolution — hashes, transitive pins, a dependency graph — and only the
  package manager can compute the new one. A package seen *only* there is
  reported with `— manual` and a reason, never silently skipped. After a fix,
  any lockfile the bump has just outdated is named so you can regenerate it.
- **A declared range.** `"openai": "^4.0.0"` in `package.json` beside a
  `package-lock.json` resolving `4.2.1` gives the component a version the
  manifest never spells; the same happens for `>=`/`~=` in `requirements.txt`
  beside a poetry or uv lock. AIROM has no single pin to rewrite there, so the
  row says so instead of offering a button that would always refuse.
- **`pom.xml`.** The Maven detector records the line of the `<dependency>` open
  tag; the `<version>` is on a later line AIROM does not track. Reported as
  `— manual` with that reason. (`build.gradle` *is* fixable — its detector
  records the line carrying the whole `group:artifact:version` coordinate.)
- **A prefix-named sibling.** The package name is matched as a whole token, so a
  `langchain` fix can never land on `langchain-core`, and `golang.org/x/mod`
  never on `golang.org/x/mod/semver`.
- **A line that moved since the scan.** The pin is re-read and re-checked for
  both the package name and the exact version the scan saw; if either has
  changed, the fix refuses and tells you to re-scan.
- **Anything outside the scan root**, and anything that is not a filesystem
  scan: `--fix` rewrites a working tree, so it is rejected for `image`, `repo`,
  and `k8s` targets.

### Verifying the fix actually builds — `--fix-verify`

Clearing every advisory and producing a manifest nothing can install is not a
fix. `--fix-verify` runs the ecosystem's own resolver in **dry-run mode** after
the edits land — it installs nothing and writes nothing to your project — and
reports whether the bumped pins still resolve *together*.

```console
$ airom scan . --fix-all --fix-verify
airom fix: updated 3 pin(s)
  requirements.txt:1  langchain==0.0.310  →  langchain==1.3.9   (langchain)
  ...

airom fix: verifying the new pins resolve (dry run — nothing is installed)
  ✖ requirements.txt — pip cannot resolve the new pins:
      ERROR: Cannot install -r requirements.txt (line 1) and (line 2) because these
      package versions have conflicting dependencies.
      The conflict is caused by:
          langchain 1.3.9 depends on langchain-core<2.0.0 and >=1.4.6
          langchain-community 0.3.27 depends on langchain-core<1.0.0 and >=0.3.66

Revert all 3 fix(es)? This re-opens the advisories they closed. [y/N]
```

This matters because the two questions are not the same one. *"Does this version
clear the advisory?"* is answered per package, from OSV. *"Do the bumped versions
resolve together?"* is a question about a dependency graph AIROM does not model,
and only the ecosystem's resolver can answer it.

| Manifest | Checked with | Note |
|---|---|---|
| `requirements.txt` | `pip install --dry-run --report` | `--report` puts pip in resolution mode, which skips the install-target checks a PEP 668 system Python would otherwise refuse on |
| `package.json` | `npm install --dry-run` | |
| `go.mod` | `go list -m all` | catches a version that does not exist and a `go.sum` the bump invalidated. Deliberately without `-e`, which would report those errors in the output and exit 0 anyway |
| everything else | — | reported as **not checked**, with the reason. `pyproject.toml`, `Cargo.toml`, and `build.gradle` resolve by writing a lockfile, and a check that mutates your tree is not a check |

**A conflict is attributed before it is acted on.** The same check also runs
*before* anything is edited, so AIROM can tell a clash the fix caused from one
the manifest already had:

```console
airom fix: checking how these manifests resolve before any change (dry run)
  ! requirements.txt does not resolve as it stands, before any fix
...
  ! requirements.txt — pip cannot resolve it, and could not before the fix either:
      ERROR: No matching distribution found for some-broken-pin==1.0.0
      the fix did not cause this; reverting it would re-open the advisories
      without repairing the clash
```

A stale `go.sum`, a peer clash a project has carried for months, a typo'd pin —
none of them are the fix's doing, and rolling real remediation back to "solve"
one would re-open live advisories while repairing nothing. So only a conflict
the fix **introduced** offers the revert. With no baseline verdict the conflict
is reported as *unknown*, not as innocent, and still offers it.

**On a conflict the fix introduced**, the pins are **kept**, never silently
rolled back. On a terminal you are offered the revert (which restores every
edited line byte-for-byte, and says out loud that it re-opens the advisories);
in CI the edits stand and the report prints the reverse edits so you can undo
them.

**It degrades, it never fabricates.** No toolchain, an old tool that lacks a
dry-run, a resolver that times out (3 min), or a refusal about the *machine*
rather than the pins — a PEP 668 "externally managed" Python, a network
error — all report **not checked** with the reason. Only the resolver actually
saying the pins clash is reported as a conflict, because "pip is not installed"
must never read as "these pins are fine", and it must never read as "these pins
are broken" either.

It needs the network and the toolchain — and runs the resolver twice, once for
the baseline — so it is **opt-in** rather than part of `--fix`.

**Ordering.** Fixes run *after* the AIBOM is emitted and the emitted document
describes the tree as the scan found it — a bill of materials for a state the
software was never in would be worse than none. For the same reason an active
`--fail-on` gate still evaluates the scanned inventory. Re-run the scan to
confirm the advisories are cleared.

## Severity and the `--fail-on` threshold

Each CVE's severity is derived from its CVSS v3.x vector (AIROM computes the
base score from the vector per the [FIRST][first] formula) and bucketed into the
standard bands: **critical** (≥ 9.0), **high** (≥ 7.0), **medium** (≥ 4.0),
**low** (> 0), or **unknown** (an advisory with no parseable CVSS v3 vector, where a
CVSS v2/v4-only or text-only record; the vector is still shown, but no score is
invented).

`cve:<severity>` is a **threshold, not an exact match**: `--fail-on cve:high`
fires on high **and** critical CVEs; `cve:medium` fires on medium and above.
Use bare `cve` to fail on any CVE at all.

## Honesty and degradation

- **A network failure is never fatal, except when it would turn a CVE gate into
  CI theater.** If OSV is unreachable or a query fails, the affected component
  simply carries no CVEs and a warning is recorded in the scan's `Stats.Warnings`
  (visible under `--stats`); the scan still succeeds and the AIBOM is never held
  hostage to a third-party API's uptime. **The one exception:** when a CVE gate
  is active (`--fail-on cve…`) *and* at least one component could not be checked,
  the scan **fails closed** with a clear error (exit 2) rather than exit 0. A
  gate that silently passes because the fetch failed is worse than no gate, so
  during an OSV outage the build errors loudly instead of reporting a false
  "clean." Re-run when OSV is reachable.
- **Absence of CVEs is not a safety claim.** It means "OSV had no advisory for
  these exact package versions at scan time," not "this dependency is safe."
  New advisories are published continuously; re-run to re-check.
- **Deduplication.** OSV often returns several advisory records (a GHSA and a
  PYSEC, say) that alias the same CVE. AIROM collapses them to one entry per id,
  keeping the most severe rating, preferring a real fixed version over a commit
  hash, and unioning the aliases, so you see one row per CVE, not one per
  advisory database.

[purl]: https://github.com/package-url/purl-spec
[osv]: https://osv.dev
[first]: https://www.first.org/cvss/v3.1/specification-document
