# Rule-Pack Schema Reference

> **Status:** authoritative contract for the v0 rule-pack format, derived from
> [ARCHITECTURE.md §6.3](./ARCHITECTURE.md#63-declarative-rule-packs--the-bright-line).
> The Go types backing this schema live in `internal/ruleengine` and stay internal in v0
> (contributors edit YAML, not Go); they graduate to `pkg/` when the format has survived
> real third-party use. **This document is the compatibility promise in the meantime** —
> the Phase 5 rule compiler implements exactly what is written here.

A rule pack is a YAML file declaring pattern-based detections: *keywords + regex over
classified text regions + a templated claim*. Anything beyond that expressive envelope — a
loop, a parser, cross-file correlation — is a Go detector, not a rule
(the bright line, [plugin-guide.md](./plugin-guide.md#the-bright-line)).

## File layout and naming

- Packs live under `rules/<category>/` — `models/`, `embeddings/`, `frameworks/`,
  `vectordb/`, `infra/`, `params/`, `prompts/`, `datasets/`.
- **One pack file per provider** (lint-enforced). `rules/models/openai.yaml`, never
  `rules/models/all-providers.yaml`. This is a deliberate architecture decision (D3): with
  hundreds of rules, monoliths are merge-conflict hotspots and defeat CODEOWNERS routing.
- The `pack:` field must equal the filename stem (`openai.yaml` ⇒ `pack: openai`).
- Fixtures and the golden live in `rules/<category>/testdata/<pack>/`.

## Top-level fields

| Field | Type | Required | Constraints |
|---|---|---|---|
| `pack` | string | yes | `[a-z0-9-]+`; must equal the filename stem |
| `version` | integer | yes | ≥ 1. **Informational only** — cache invalidation is driven by the content hash of the effective compiled ruleset, never by this number (see [Cache keys](#cache-keys)). Bump it as a human-readable change marker. |
| `rules` | list | yes | ≥ 1 rule |

## Rule fields

| Field | Type | Required | Summary |
|---|---|---|---|
| `id` | string | yes | Globally unique across **all** packs and layers |
| `kind` | string | yes | Component kind the claim produces |
| `provider` | string | no | Normalized provider slug |
| `languages` | list of strings | no | Language gate; default: all supported |
| `keywords` | list of strings | **yes** | Aho–Corasick prefilter literals; **lint-rejected if missing or empty** |
| `pattern` | string | yes | Go RE2 regex; named groups become template variables |
| `regions` | list of strings | no | Subset of `[code, string]`; default both |
| `claim` | map | yes | Templated component claim |
| `relations` | list | no | Templated relationship claims |
| `capture_params` | map | no | Same-call-site generation-parameter capture |
| `confidence` | float | yes | Per-sighting confidence, `0 < c ≤ 0.99` |
| `disable` | bool | overlay only | Disables an existing rule by ID (see [Merge semantics](#the-three-rule-layers-and-merge-semantics)) |

### `id`

Format `<pack>/<slug>`, e.g. `openai/model-literal`. Constraints:

- **Globally unique across every pack in every layer.** Duplicates are a lint error, and a
  duplicate surviving to runtime panics at startup (fails CI, never silently shadows).
- Stable forever once merged: the ID becomes the occurrence `DetectorID`
  (`rules/` + id, e.g. `rules/openai/model-literal`), which is the SARIF `ruleId` and part
  of SARIF `partialFingerprints`. Renaming an ID breaks downstream suppressions — treat it
  like a public API symbol.
- In non-overlay packs, the prefix before `/` must equal `pack:`.

### `kind`

One of the rule-expressible component kinds:

```
hosted-llm · embedding-model · framework · library · vector-db ·
prompt · dataset · ai-config · infra · service
```

Not expressible by rules, by design: `local-model-file` (binary header parsers own it),
`rag-pipeline` (synthesized by phase-2 detectors), `application` (the scan root, minted by
the assembler).

### `provider`

Normalized provider slug (`openai`, `anthropic`, `fireworks`, `aws-bedrock`, …). Feeds both
`Component.Provider` and the identity `CanonicalKey.Provider`
([ARCHITECTURE.md §9.1](./ARCHITECTURE.md#91-identity--canonicalkey)) — so spelling it
consistently across rules is what makes cross-rule dedup work. Per-provider alias tables
(shipping alongside the packs) feed the assembler's normalizer chains; the rule carries the
raw slug.

### `languages`

Subset of the supported set:

```
python · javascript · typescript · go · java · rust · csharp · kotlin
```

Omitted = the rule runs on all of them. Region classification comes from the per-language
region lexers (for Go, the stdlib scanner). A rule never runs on files whose classified
language isn't in this list — it's part of the compiled selector, evaluated before any
content work.

### `keywords` — mandatory, lint-enforced

Literal substrings, matched **case-sensitively** against the file's code and string regions
by a single Aho–Corasick trie built over *all* packs' keywords at startup. The rule's regex
executes only if at least one keyword hits. Consequences:

- **A rule with no keywords is rejected by `airom rules lint`** — nobody can ship an
  un-prefiltered regex. This is what keeps hundreds of rules × 100k files cheap (invariant
  P3; the shape gitleaks and semgrep both proved).
- Include every casing variant you need (`"ChatOpenAI"`, `"chat_openai"`).
- Prefer selective literals (≥ 4 characters, provider-distinctive). Lint warns on keywords
  so short or common that they defeat the prefilter.
- Comments are never scanned — a keyword appearing only in a comment cannot activate the
  rule.

### `pattern`

A Go [RE2](https://github.com/google/re2/wiki/Syntax) regular expression (no backtracking,
no lookaround — linear-time by construction). Compiled once at startup; a non-compiling
pattern fails lint.

- **Named groups** `(?P<name>…)` are the data channel: each named group's match is recorded
  in `Occurrence.Fields[name]` and is referenceable as `${name}` in templates.
- **Every named group must be referenced** — by a `claim` template, a
  `relations[].target.from_field`, or by having semantic meaning as a captured field the
  assembler consumes (`model` is the canonical example, §9.5). An unreferenced named group
  is a lint error: it's either dead weight or a typo.
- Conversely, every `${var}` in a template must name an existing named group (lint error
  otherwise).
- YAML tip: use single-quoted scalars and double `''` for a literal single quote, as in the
  examples below.

### `regions`

Which classified text regions the pattern may match: any subset of `code` and `string`
(default: both). The region lexer classifies every file into code / comment / string
regions before matching; **comment regions are never scanned** — not even by the keyword
prefilter — so there is no `comment` value. Typical choices:

- Model-ID literals: `[code, string]` or `[string]` (the ID is a quoted literal).
- Import/call patterns: `[code]` — but note JS/TS module specifiers
  (`from "openai"`) are *string* regions; use `[code, string]` when matching them.

### `claim`

The templated component claim. The assembler — never the rule — normalizes names, mints
identity, dedups, merges, and computes final confidence (invariant P4).

| Subfield | Required | Notes |
|---|---|---|
| `name` | yes | Template; usually `"${model}"` or a fixed SDK/package name |
| `group` | no | Org/namespace (`"meta-llama"`), templated |
| `version` | no | Raw version claim, templated. Version-unknown sightings fold into an existing versioned component rather than minting a twin (§9.1) |

`kind` and `provider` come from the rule fields above; purl is **derived** by the assembler
(hosted models get none, decision D9); hashes don't apply to pattern matches.

### `relations`

Edges are first-class rule output — no Go needed to claim a relationship:

```yaml
relations:
  - { type: uses, target: { kind: hosted-llm, from_field: model } }
```

| Subfield | Notes |
|---|---|
| `type` | One of the relationship types in [ARCHITECTURE.md §5](./ARCHITECTURE.md#5-core-domain-model-pkgairom): `uses`, `depends-on`, `served-by`, `queries`, `embeds-with`, `prompted-by`, `trained-on`, `derived-from`, `configures`, `contains` |
| `target` | Exactly **one** of the three hint forms below (lint-enforced) |

Target hint forms:

1. `{ kind: <kind>, name: "<template>" }` — a concrete (possibly templated) target name.
2. `{ kind: <kind>, from_field: <field> }` — the target's name is whatever the named group
   or captured param `<field>` matched at this occurrence. `from_field` must reference a
   named group in `pattern` or a name in `capture_params.names` (lint-enforced).
3. `{ local_ref: <rule-id> }` — links to the claim another rule of the same pack made **in
   the same file** (e.g. a client-constructor rule linking to its own import rule).

Resolution happens in the assembler **after** all components exist. A hint that matches no
component becomes a warning in `Inventory.Stats` — **never a phantom node, never a guessed
edge**.

### `capture_params`

Same-call-site generation-parameter capture — the highest-precision layer of the AI-config
binding story ([ARCHITECTURE.md §9.5](./ARCHITECTURE.md#95-ai-config--model-attachment-layered-refusal-first)):

```yaml
capture_params:
  within_lines: 12
  names: [temperature, top_p, top_k, max_tokens, max_output_tokens, seed,
          stop, reasoning_effort, response_format]
```

| Subfield | Required | Constraints |
|---|---|---|
| `within_lines` | yes | Integer, 1–64. Window (in lines, from the match) within which kwarg-style bindings are captured |
| `names` | yes | Non-empty list of parameter names to capture |

Captured bindings land in `Occurrence.Fields`. The assembler promotes them into
provenance-carrying `BoundParam`s on a model's facet **only when the same occurrence also
carries a `model` binding** — call-site capture beats every weaker proximity heuristic, two
call sites with different temperatures stay two `BoundParam`s, and nothing is ever averaged
or guessed.

Binding **values** may live in string literals regardless of the rule's own `regions`
(`model="gpt-4.1"` at a `[code]` call site), but the binding **key** must lie in a region
the rule declares — `temperature:` inside a prose string is not a kwarg. When a captured
value is a bareword identifier rather than a literal (`model=BASE_MODEL`), it is resolved
against the file's single-literal assignment *statements* (`BASE_MODEL = "gpt-4o-mini-2024-07-18"`,
anchored at statement position — call-site kwargs, default args, and tuple elements never
bind); an identifier assigned two different literals is ambiguous and stays verbatim —
refusal over guessing.

### `confidence`

Float, `0 < c ≤ 0.99` — the confidence of **one sighting by this rule alone**. Rules cannot
assert `1.0`: certainty is reserved for hash-comparison against known weights and (v2)
verified attestations (§9.3). Corroboration is the assembler's job — grouped noisy-OR
across detection methods — so calibrate the single sighting honestly:

- `0.85–0.9`: a provider-distinctive model-ID literal in a `model=`/`model:` position.
- `0.6–0.75`: an SDK import or call-site shape (tells you the library is present, not which
  model).
- `≤ 0.5`: weak contextual hints.

Repetition cannot launder into certainty: twelve sightings of one 0.85 rule assemble to
≈ 0.87, not 0.999.

## Fixtures and the lint contract

Every rule ships **at least one positive and at least one negative fixture case** —
CI-enforced by `airom rules lint`. Cases are annotated in the fixture source (comment syntax
of the host language; annotation applies to the next line, or to the same line when
trailing):

```python
# airom: fireworks/model-literal        ← next line MUST produce this finding
# airom-ok: fireworks/model-literal     ← next line MUST NOT produce this finding
```

The pack's golden (`testdata/<pack>/findings.golden.json`, written by
`go test ./rules/... -update`) pins the complete findings output over the fixtures.

<a id="lint-contract"></a>**The full lint rule set** (`airom rules lint`, runs in CI on
every rules PR; command lands in Phase 3, complete validation with the Phase 5 compiler):

1. `pack` matches the filename stem; one provider per file.
2. Every rule `id` is well-formed and globally unique across all packs and layers.
3. Every `pattern` compiles as RE2.
4. **`keywords` is non-empty** for every rule.
5. Every named group is referenced; every `${var}` is backed by a named group.
6. `regions` ⊆ {code, string}; `languages` ⊆ the supported set; `kind` is rule-expressible.
7. `relations[].target` has exactly one hint form; `from_field` references an existing
   field source.
8. `capture_params.within_lines` ∈ [1, 64]; `names` non-empty.
9. `confidence` ∈ (0, 0.99].
10. **≥ 1 positive and ≥ 1 negative fixture annotation per rule**; goldens up to date.

## The three rule layers and merge semantics

The effective ruleset is assembled from up to three layers:

```
1. embedded defaults    rules/**  compiled into the binary via go:embed
                        (offline by construction, versioned with the release)
        ▼  merged by rule ID
2. user overlay         --rules extra.yaml (repeatable, applied in flag order)
        ▼  merged by rule ID
3. remote registry      v2 — OCI-distributed packs; reserved slot, pairs with
                        signing/trust-policy work (see ROADMAP.md). Precedence and
                        trust rules are settled with that design.
```

Overlay merge is **by rule ID**, with three operations:

- **Add** — a rule whose ID doesn't exist yet. New IDs in an overlay must be namespaced by
  the overlay's own `pack` name.
- **Override** — a rule whose ID matches an existing rule **replaces it wholly**. There is
  no field-level merging: the overlay rule must be complete and passes the same lint.
- **Disable** — an entry consisting of just the ID and `disable: true` removes the rule
  from the effective set:

  ```yaml
  pack: mycorp-overrides
  version: 1
  rules:
    - id: openai/model-literal
      disable: true
  ```

Later layers win; within the `--rules` flag list, later files win. `airom rules list` shows
the effective ruleset with each rule's originating layer.

## Compilation and runtime behavior

`rules.Compile()` runs **once at process startup** (gitleaks lineage):

1. Parse every pack in every layer; apply merge semantics.
2. Validate the entire lint contract above; any violation aborts startup with the offending
   pack, rule, and reason.
3. Compile every regex; build **one Aho–Corasick trie over all packs' keywords**.
4. Hand the compiled `*Matcher` to the rule-engine detector via its constructor — no
   globals, no `init()` registration (D4).

Per file at scan time:

1. The selector index has already gated on language/size (compiled from the rule metadata).
2. The region lexer classifies the file into code / comment / string regions.
3. The trie runs over the code + string regions only. No keyword hit ⇒ the file is done —
   this eliminates the overwhelming majority of files at ~memcpy speed.
4. Only rules whose keywords hit have their regex executed, and only within their declared
   regions.
5. Matches template into `Finding`s: claim + occurrence (with `Fields` from named groups
   and `capture_params`) + relation claims. Method is always `source-code-analysis`;
   snippet capture (≤ 200 bytes, sanitized) is handled by the engine.

Rule findings then flow through the same assembler as every code detector's: identity via
`CanonicalKey`, keep-and-relate merge, grouped noisy-OR confidence
([ARCHITECTURE.md §9](./ARCHITECTURE.md#9-assembly-identity-dedup-confidence-params)).

<a id="cache-keys"></a>## Cache keys: rules are self-invalidating

The SHA-256 of the **effective compiled ruleset** (all three layers, post-merge, canonical
serialization) participates in the cache namespace
([ARCHITECTURE.md §10](./ARCHITECTURE.md#10-caching-internalcache-bbolt)):

```
namespace = sha256(detectorVersions ‖ effectiveRulesetSHA256 ‖ sizeCaps ‖ ignoreConfig)
```

Any change to any rule — embedded or overlay, add/override/disable — produces a new
namespace, and every cached finding is structurally invisible to the new configuration.
This is why `version:` is informational: rules-as-data self-invalidate on **content**, which
eliminates the forgotten-version-bump stale-cache bug for the entire fast-moving detection
surface. The flip side: editing rules invalidates the whole cache namespace — correctness
over cache warmth, and `airom clean` prunes old namespaces.

## Worked example

The canonical pack from the architecture, in full:

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
    # The key matches any model-naming identifier: model=, "model":, BASE_MODEL =, model_id =.
    pattern: '\b(?i:[a-z0-9_]*model[a-z0-9_]*)\s*[:=]\s*["''](?P<model>gpt-[\w.\-]+|o[34][\w.\-]*)["'']'
    regions: [code, string]                        # never match inside comments
    claim: { name: "${model}" }
    confidence: 0.85

  - id: openai/chat-call
    kind: library
    provider: openai
    keywords: ["chat.completions.create", "responses.create"]
    pattern: '\.(chat\.completions|responses)\.create\s*\('
    regions: [code]                                # the param window still sees strings
    claim: { name: "openai" }
    relations:                                     # edges from YAML — no Go needed
      - { type: uses, target: { kind: hosted-llm, from_field: model } }
    capture_params:                                # same-call-site binding (§9.5)
      within_lines: 12
      names: [temperature, top_p, top_k, max_tokens, max_output_tokens, seed,
              stop, reasoning_effort, response_format]
    confidence: 0.7
```

For a from-scratch walkthrough of authoring, testing, and shipping a pack (Fireworks AI,
with fixtures and goldens), see [plugin-guide.md](./plugin-guide.md#path-a--a-rule-pack-start-to-finish).

## What rules cannot do

By design, a rule cannot: read a second file, parse a structured format, loop, compute a
hash, mint an ID, set a purl, assert confidence 1.0, or emit `local-model-file` /
`rag-pipeline` / `application` components. If the detection you want needs any of those,
it's a Go detector — [plugin-guide.md, Path B](./plugin-guide.md#path-b--a-code-detector-start-to-finish).
