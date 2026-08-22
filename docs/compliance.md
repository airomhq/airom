# Compliance framework mapping

`airom scan . --compliance <framework>` maps the assembled AIBOM onto a named
AI-governance framework's controls. For each control it decides **met / gap /
manual** and attaches the component evidence behind the verdict, projecting the
result into the CycloneDX attestation model.

> **A mapping, never a certification.** Most AI-governance frameworks are
> largely organizational *process*: policy, documentation, human oversight,
> and post-market monitoring, none of which a static code scan can verify. AIROM marks
> those controls **manual** and emits **no score** for them: it never asserts a
> conformance figure it cannot back. An `evidence_of` "met" points at the
> concrete components that satisfy it, with their `file:line`; a `gap_if` "met"
> asserts the *absence* of a gap (e.g. no scanner-detected risk), so it carries
> a score with nothing to list. That is the claim.

## Usage

```bash
# One framework, into CycloneDX + a native record
airom scan . --compliance nist-ai-rmf -o cyclonedx=bom.json -o json=airom.json

# Repeatable
airom scan . --compliance nist-ai-rmf --compliance owasp-agentic
```

Frameworks are embedded; `--compliance` with an unknown id fails loudly with the
valid set. Run `airom fs --help` for the shipped list.

## The three verdicts

| State | Meaning | Score | Evidence |
|-------|---------|-------|----------|
| `met` | an `evidence_of` expression matched (or a `gap_if` did not) | `1.0` | the matching components |
| `gap` | a `gap_if` expression matched (or an `evidence_of` did not) | `0.0` | the counter-evidence components |
| `manual` | not automatable; requires human attestation | *(none)* | n/a |

Severity/score is a **fixed function of the state**, never judgment at scan
time, so output is deterministic.

## How it maps

A control declares exactly one mapping directive over the inventory:

- `evidence_of: <expr>`: components matching `<expr>` are supporting evidence;
  ≥1 → `met`, else `gap`.
- `gap_if: <expr>`: components matching `<expr>` are counter-evidence; ≥1 →
  `gap`, else `met`.
- `manual: true`: reported `manual`, no score.

`<expr>` is a subset of the [`--fail-on`](./cli.md) grammar: a component kind
(`hosted-llm`, `local-model-file`, …), `*` (any component), or a risk selector
(`risk`, `risk:high`, `risk:unsafe-load`), joined by `|` (OR) and `&` (AND). So
"the AIBOM inventories the AI methods" maps to the presence of model/framework
components, and "security is evaluated" maps to the [artifact-risk
overlay](./risks.md) via `gap_if: risk`.

## How it appears in output

| Format | Where |
|--------|-------|
| CycloneDX | `definitions.standards[]` (the framework + its `requirements[]`) and `declarations`, with AIROM as a first-party `assessor`, one `claim` + `attestation.map[]` entry per control, with a graded `conformance.score` (omitted for manual). Evidence points at the component `bom-ref`s. |
| Compliance report (`-o compliance`) | A human-readable Markdown report: per framework a summary line (`N controls: X met, Y gap, Z manual`) and a table of every control with its state and evidence. |
| Native JSON / YAML | `inventory.compliance[]` holding `{framework, name, version, controls[]}`, each control `{id, title, state, score, rationale, evidence[], counterEvidence[]}`. |

```bash
# The Markdown report alongside the machine-readable BOM
airom scan . --compliance nist-ai-rmf -o compliance=report.md -o cyclonedx=bom.json
```

## Gating in CI

`--fail-on` gates on a **gap** (a manual control is not a failure; a met is a pass):

| Selector | Fires when |
|----------|-----------|
| `compliance:gap` | any control in any evaluated framework is a gap |
| `compliance:<framework>` | any control in that framework is a gap |
| `compliance:<framework>:<control>` | that specific control is a gap |

```bash
airom scan . --compliance nist-ai-rmf --exit-code 1 --fail-on "compliance:gap"
```

A compliance selector is inventory-level, so it cannot be `&`-combined with a
component term (use `|`), and `--fail-on` referencing compliance requires
`--compliance` to have been given, because gating on a framework you never evaluated is
a configuration error, not a silent pass.

> **The gate evaluates the full assembly.** Like every `--fail-on` selector,
> `compliance:*` is evaluated over the whole assembled inventory, and `--min-confidence`
> does **not** relax it. The emitted report *does* honor `--min-confidence` (it is
> presentation), so under a high `--min-confidence` a run can fail on a gap the
> report shows as met. That asymmetry is deliberate: a CI gate you could bypass by
> hiding low-confidence components would be no gate at all.

The mapping stays **deterministic and offline**: the frameworks are static
data, no LLM, no network.

`--min-confidence` is a presentation filter, so the compliance overlay is
re-mapped over the surviving components before it is emitted: the mapping always
describes the inventory you are looking at, and never references a component the
filter dropped.

## Frameworks

- **`colorado-ai-act`**: Colorado AI Act (SB 24-205 / C.R.S. § 6-1-1701 et seq.). Enforces mandatory risk management programs, annual algorithmic impact assessments (§ 6-1-1703), consumer disclosures (§ 6-1-1704), and 90-day discrimination incident notification protocols (§ 6-1-1705).
- **`nyc-ll144`**: New York City Local Law 144 (Admin Code § 20-870 et seq.). Enforces independent bias audits, adverse impact ratio threshold calculations (EEOC 80% four-fifths rule), and 10-business-day advance candidate notices for Automated Employment Decision Tools (AEDTs).
- **`ca-ab2013`**: California AB 2013 Generative AI Training Data Transparency Act (Civ. Code § 1798.500 et seq.). Enforces public summaries of training datasets, source data licensing, and biometric/PII data collection disclosures.
- **`illinois-bipa`**: Illinois Biometric Information Privacy Act (740 ILCS 14/15(a)-(e)). Enforces written retention schedules, permanent deletion triggers upon satisfaction of purpose, informed consent mandates, and bans on profiting from biometric identifiers.
- **`texas-traiga`**: Texas Responsible AI Governance Act (TRAIGA / Tex. Gov't Code § 2054.601-604). Enforces state automated decision system registry filings, impact assessments, and public interest safeguards.
- **`virginia-vcdpa`**: Virginia Consumer Data Protection Act (Va. Code § 59.1-575-580). Enforces mandatory Data Protection Assessments (DPAs) for targeted profiling, consequential decisions, and biometric processing.
- **`nist-ai-rmf`**: NIST AI Risk Management Framework 1.0. A representative subset: the inventory/documentation subcategories (MAP) are auto-evaluated from the AIBOM, security/resilience (MEASURE-2.7) maps to the risk overlay, and the governance subcategories (GOVERN, MANAGE) are `manual`.
- **`owasp-agentic`**: OWASP Agentic AI Threats and Mitigations. Tracks prompt injection, tool abuse, untrusted model artifacts, and privilege boundaries.

_All framework YAML specifications reside in `internal/compliance/specs/` and are embedded directly into the standalone binary._
