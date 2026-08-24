# Benchmark design: measuring what the scanner actually does

> **Status:** Live. The evaluator is `airom bench`; the corpus is
> [airomhq/airom-bench](https://github.com/airomhq/airom-bench) — 13 synthetic
> entries and 3 real-world ones; the first baseline is `v0.4.3`; and CI runs
> the gate **report-only** for two releases per §5. Any precision, recall, or
> calibration number cited in AIROM's docs must come from this benchmark and
> carry its `n`. Calibration stays unclaimed until §6's conditions are met.

## 1. Why

AIROM's detection quality rests today on fixtures and goldens: every rule
ships a positive and negative case, and eleven end-to-end fixture repos pin
the full pipeline's output. That proves the rules do what their authors
intended. It does not measure how often the intention is wrong.

The evidence is our own history. Scanning `huggingface/transformers` once
attributed 226 hosted models from docstring examples, 42% of everything
reported in that scan (rule-schema.md, "docstring"). Every fixture passed
while it happened. A rule can be perfect against its handcrafted case and
wrong about the world.

The confidence scores have the same gap one level up. They are
evidence-weighted, deliberately not called calibrated (ARCHITECTURE §9.3),
and the word comes back only when something measures calibration error
against ground truth. This benchmark is that something.

## 2. What is measured

All metrics are computed by `airom bench` against a labeled corpus, per
scan, then aggregated.

| Metric | Definition | Why it is here |
|---|---|---|
| Component precision | matched reported / all reported | Are the findings real? |
| Component recall | matched labels / all labels | What did we miss? |
| Per-kind P/R | the above, per `ComponentKind` | An aggregate hides one kind collapsing |
| Per-language P/R | the above, per source language | Python health says nothing about Kotlin |
| Version accuracy | on matched: exact / honestly-absent / **wrong** | A wrong version poisons the CVE overlay; worse than no version |
| Provider accuracy | on matched: right / absent / wrong | Right model, wrong provider is still wrong |
| Location validity | on matched: does `file:line` point at labeled evidence? | Evidence is the product; a dangling pointer is a false claim |
| Trap violations | reported components matching a `forbidden` label | The docstring lesson, as a permanent metric |
| Unknown rate | `unknowns` / files processed | How much input produced no verdict |
| Truncation rate | `filesTruncated` / files processed | Read straight off the assurance block |
| Per-band precision | observed precision of findings in each confidence band, with counts | The calibration study, §6 |

Determinism and peak RSS are already gated elsewhere (P7 diff test, perf
gates); the benchmark reports throughput but never gates on it.

## 3. The corpus

### 3.1 Two tiers, one rule about contamination

**Tier S (synthetic):** constructed repos, labels correct by construction.
They exist to cover axes real repos cover unevenly: one repo per language
per major kind, plus adversarial shapes (docstrings, comments, README
mentions, test fixtures, minified bundles). Tier S measures coverage, not
honesty.

**Tier R (real):** pinned snapshots of public repositories, hand-labeled.
This tier is the headline number and the only tier quoted anywhere.

**The contamination rule:** the corpus is held out. The eleven
`internal/e2e` fixtures and every rule fixture are development data; rules
were written against them, so they can never appear in the corpus. The
reverse also binds: a corpus repo may not be copied into a rule's fixtures.
When a corpus failure motivates a rule fix, the fix ships with a NEW
handcrafted fixture reproducing the shape, never the corpus content. A
benchmark you can study for is a fixture suite with extra steps.

### 3.2 Selection criteria for Tier R

- Permissive license (MIT, Apache-2.0, BSD), recorded per entry; the corpus
  redistributes snapshots, so this is a hard requirement.
- Whole repos, pinned by commit SHA and content hash. No subtrees: manifests
  at the root are part of what detection sees.
- Small enough to scan in CI (soft cap 50 MB per snapshot), large enough to
  be real.
- Jointly covering: every language the rule engine lexes, every major kind,
  at least two repos with NO AI at all (pure-negative repos are what make
  precision honest), and at least one known trap-rich repo.
- Target size: 12 to 20 repos for v1. Small enough to label carefully, large
  enough that per-kind numbers are not all noise. Per-band calibration
  counts will still be thin; §6 says how that is handled honestly.

### 3.3 Where it lives

`airomhq/airom-bench`, a separate repository, same pattern as airom-rules:

```
airom-bench/
  corpus/
    <repo-name>/
      snapshot.tar.gz       # the pinned tree, content-addressed (stdlib-decodable: no new dependency for the extractor)
      truth.yaml            # the labels
      MANIFEST.yaml         # upstream URL, commit, license, sha256, labeler
  schema/truth-schema.json
  baselines/                # per-airom-release result JSON (the gate input)
```

The evaluator ships in the scanner (`airom bench <corpus-dir>`), so the
methodology is inspectable and anyone can reproduce the published numbers
with two commands. CI fetches airom-bench at a pinned commit; the scanner
repo never vendors the corpus.

## 4. Labels

`truth.yaml`, versioned like every other data contract:

```yaml
schemaVersion: 1
labeler: "<who>, <date>"
scan:
  args: []                # non-default flags, if the repo needs any
expected:
  - kind: hosted-llm
    name: gpt-4o-mini     # canonical, post-normalization spelling
    provider: openai
    version: ""           # "" = version must be ABSENT (honestly unknown)
    evidence:
      - file: src/agent.py
        lines: [40, 55]   # tolerant range, not an exact line
  - kind: framework
    name: langchain
    version: "0.3.0"      # exact pin the manifest declares
    evidence:
      - file: requirements.txt
forbidden:
  - kind: hosted-llm
    name: claude-3-opus
    reason: appears only in a README comparison table
    evidence:
      - file: README.md
notes: |
  Free-form labeling decisions, for the next auditor.
```

Semantics:

- **Matching** is 1:1 greedy on `(kind, normalized name)`. Surplus reported
  components are false positives; surplus labels are false negatives. A
  split-brain (one real thing reported twice) is one match plus one FP,
  which is the honest reading: the consumer sees two claims.
- **Attributes are graded, not matched on.** A found component with a wrong
  version is a recall success and a version failure. Collapsing those into
  one number is how a scanner that finds everything and describes it wrong
  looks good.
- **`version: ""` is an assertion**, not a shrug: the correct output is an
  absent version, and reporting a guessed one is a *wrong-version* failure.
  This is the tri-state discipline applied to the benchmark itself.
- **`forbidden` entries are traps**: things a naive scanner reports.
  Reporting one is counted separately from ordinary FPs, because each trap
  encodes a lesson already learned once.
- Components AIROM marks test-scoped count only if the label says
  `scope: test`; the corpus grades the default presentation, since that is
  what users see.

Labeling method: label from reading the repo, before looking at any
scanner's output. Then run AIROM and at least one other tool as a
completeness probe; anything they surface that reading missed is verified by
hand before it may become a label. Every label carries evidence, so the next
auditor can check the labeler. Label errors found later are fixed by commit
to airom-bench with the reasoning in the message; labels are code.

## 5. The gate

`baselines/<airom-version>.json` records the full metric set at each
release. CI runs the benchmark on every PR touching `rules/`, detectors, the
lexers, or the assembler, and compares against the newest baseline:

| Change | Policy |
|---|---|
| Precision drops > 1pt (overall or any kind with ≥ 20 labels) | fail |
| Recall drops > 1pt (same floors) | fail |
| Trap violations increase | fail, no threshold |
| Wrong-version count increases | fail, no threshold |
| Anything improves | update the baseline in the same PR |

Exit codes follow the CLI's contract (docs/cli.md): **1** for a regression,
the same code `--fail-on` uses, because a regression is a policy failure;
**2** only when the benchmark could not run at all — an unreadable corpus, a
malformed truth file, bad flags. CI has to tell "the harness is broken" from
"detection got worse", because the response to each is different.

First two releases run **report-only**: the numbers publish, the gate does
not block. Enforcement begins once the numbers have survived two releases of
scrutiny, because gating on an unvalidated measurement enforces its bugs.

## 6. The calibration study

For every scan, each matched-or-FP finding contributes
`(confidence, correct?)`. Bucketed by the existing bands (≥0.9, 0.6–0.9,
<0.6), the benchmark reports observed precision per band next to the band's
nominal range, with counts:

```
band        n     observed precision
>=0.9      412    0.97
0.6-0.9    155    0.81
<0.6        63    0.54
```

Rules for honesty:

- Counts publish alongside rates. A band with n=12 is labeled insufficient,
  not rounded into a claim.
- No metric is quoted without its n anywhere in AIROM's docs or site.
- The word "calibrated" returns to AIROM's vocabulary only when this table
  exists in CI, its bands are monotone, and each band's observed precision
  falls inside its nominal range across two consecutive releases. Until
  then the docs keep saying evidence-weighted. If the table shows the bands
  are wrong, the bands change to fit the data, not the other way around.

## 7. Build order

1. Evaluator: `airom bench` consuming the corpus layout, emitting the
   metric JSON and a markdown report. Testable immediately against Tier S.
2. Tier S: one repo per language per major kind, plus the adversarial set.
3. Tier R: candidate list with licenses verified, then labeling, the slow
   part. Start with 6 repos including one pure-negative; grow to 12–20.
4. Baseline at the next release; two report-only cycles; then enforce.

## 8. What this deliberately does not do

No relationship precision/recall in v1: labeling edges honestly is much
harder than labeling components, and a half-labeled edge set would grade
correct edges as FPs. It joins v2 with its own schema rev. No LLM-assisted
labeling: labels are the ground truth everything else is measured against,
and putting an unmeasured tool inside the measuring instrument defeats it.
No aggregate "quality score": the metric table is the deliverable, and any
single number would immediately become the only one anyone reads.
