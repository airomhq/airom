# CVE overlay

AIROM's core scan is offline and deterministic: it reports what an artifact
*is*. The **CVE overlay** adds what is *known about it today* — it matches the
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
  materials — so disable it (`--no-cve`) when you need a byte-stable BOM.

> **Scope: AI dependencies, not a general-purpose SCA.** The overlay queries
> only the components AIROM inventories — the AI/ML frameworks, SDKs, and
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
```

The overlay composes with everything else — `--compliance` frameworks that map
to "known vulnerabilities" see the CVEs (it runs before compliance), and every
output format projects them.

## How CVEs appear in output

| Format | Where |
|--------|-------|
| CycloneDX | top-level `vulnerabilities[]` — the CVE `id`, `source.name: osv.dev`, a `ratings[]` entry with `method: CVSSv31`, the real `score`, `severity`, and `vector`, aliases as `references[]`, and `affects[].ref` pointing at the component's `bom-ref`. The first fixed version rides in an `airom:cve.fixedVersion` property. |
| SARIF | a `cve/<id>` rule carrying the GitHub `security-severity` property — the **real CVSS base score** here, not the synthetic marker the risk rules use — and a result (level `error`/`warning`/`note` by severity) anchored to the manifest line that declared the vulnerable package. |
| Native JSON / YAML | `component.vulnerabilities[]` — `{id, aliases, severity, score, vector, summary, fixedVersion, source, url}`. |
| Table | a `VULN` column on the component (top severity + count, e.g. `high (2)`), a `Vulnerabilities` breakdown in the summary panel, and a per-CVE detail table below — `LIBRARY / VULNERABILITY / SEVERITY / STATUS / INSTALLED / FIXED / TITLE`, most-severe first. Per-package columns (`LIBRARY`, `INSTALLED`, `FIXED`) merge vertically across a package's CVEs, Trivy-style, so the name and versions show once and span the group. |
| `--fail-on` | `cve` (any CVE), or `cve:<severity>` (a **threshold** — see below). |

## Severity and the `--fail-on` threshold

Each CVE's severity is derived from its CVSS v3.x vector (AIROM computes the
base score from the vector per the [FIRST][first] formula) and bucketed into the
standard bands: **critical** (≥ 9.0), **high** (≥ 7.0), **medium** (≥ 4.0),
**low** (> 0), or **unknown** (an advisory with no parseable CVSS v3 vector — a
CVSS v2/v4-only or text-only record; the vector is still shown, but no score is
invented).

`cve:<severity>` is a **threshold, not an exact match**: `--fail-on cve:high`
fires on high **and** critical CVEs; `cve:medium` fires on medium and above.
Use bare `cve` to fail on any CVE at all.

## Honesty and degradation

- **A network failure is never fatal — except when it would turn a CVE gate into
  CI theater.** If OSV is unreachable or a query fails, the affected component
  simply carries no CVEs and a warning is recorded in the scan's `Stats.Warnings`
  (visible under `--stats`); the scan still succeeds and the AIBOM is never held
  hostage to a third-party API's uptime. **The one exception:** when a CVE gate
  is active (`--fail-on cve…`) *and* at least one component could not be checked,
  the scan **fails closed** with a clear error (exit 2) rather than exit 0. A
  gate that silently passes because the fetch failed is worse than no gate — so
  during an OSV outage the build errors loudly instead of reporting a false
  "clean." Re-run when OSV is reachable.
- **Absence of CVEs is not a safety claim.** It means "OSV had no advisory for
  these exact package versions at scan time," not "this dependency is safe."
  New advisories are published continuously; re-run to re-check.
- **Deduplication.** OSV often returns several advisory records (a GHSA and a
  PYSEC, say) that alias the same CVE. AIROM collapses them to one entry per id,
  keeping the most severe rating, preferring a real fixed version over a commit
  hash, and unioning the aliases — so you see one row per CVE, not one per
  advisory database.

[purl]: https://github.com/package-url/purl-spec
[osv]: https://osv.dev
[first]: https://www.first.org/cvss/v3.1/specification-document
