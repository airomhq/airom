# Your First Detector in Under an Hour

This guide walks both ways of extending AIROM's detection surface, end to end:

- **Path A, a declarative rule pack (YAML).** No Go. This covers ~80 % of the detection
  surface and 100 % of the fast-moving surface (new model IDs, new SDK call patterns, new
  vector-DB clients). Target time: **under one hour**, and that target is CI-verified, the
  walkthrough below is the canonical one-hour contributor story from
  [ARCHITECTURE.md §6.5](./ARCHITECTURE.md#65-the-one-hour-contributor-story-north-star-documented--ci-verified).
- **Path B, a code detector (Go).** For anything a pattern can't express: binary headers,
  archive formats, manifest parsing, cross-file logic.

## The bright line

Before anything else, decide which path you're on. This rule is load-bearing, reviewers
enforce it, and PRs on the wrong side of it get redirected:

> **If the detection is expressible as *keywords + regex over classified text regions + a
> templated claim*, it's YAML. The moment you need a loop, a parser, or two files, it's Go.**

| You want to detect… | Path |
|---|---|
| A new hosted-model ID vocabulary (a provider shipped `foo-large-2`) | **A, rules PR, never a release** |
| An SDK's call sites, imports, client constructors | **A** |
| Framework / vector-DB / serving-client usage patterns | **A** |
| Generation parameters near a call site | **A** (`capture_params`) |
| A binary weights format (magic bytes + header fields) | **B** |
| An archive or manifest format (zip, lockfile, TOML) | **B** |
| Anything that correlates two files (`config.json` + `model.safetensors`) | **B** (a phase-2 `ProjectDetector`) |

One more invariant to internalize before you write anything (it shapes both paths):
**detectors emit claims, never components** (architecture invariant P4). Your output is a
`Finding`, a raw claim plus an occurrence. Identity, dedup, merging, and confidence are
assembler monopolies; the `Finding` type has no ID field, so you physically cannot break
identity or caching.

---

## Path A: a rule pack, start to finish

We'll add support for **Fireworks AI**: hosted-model IDs
(`accounts/fireworks/models/llama-v3p1-70b-instruct`) and the `fireworks-ai` SDK, in Python
and TypeScript.

### A.0 Prerequisites

- A clone of the repository. No Go knowledge needed; a Go toolchain is needed only to run
  the golden test driver (`go test`).
- The `airom` binary (`go run ./cmd/airom` works). The CLI command surface used below lands
  in **Phase 3**; until then the same validations run through the Go test driver noted at
  each step.

### A.1 Scaffold the pack

```console
$ airom dev new-rulepack fireworks
created rules/models/fireworks.yaml
created rules/models/testdata/fireworks/usage.py
created rules/models/testdata/fireworks/usage.ts
```

> `airom dev new-rulepack` arrives with the CLI command tree in **Phase 3**; its scaffold
> templates ship alongside the embedded packs in **Phase 6**. Until then, create the three
> files by hand exactly as shown below. The scaffold produces nothing you can't type.

Layout rule (lint-enforced): **one rule pack file per provider**, in the category directory
that fits (`rules/models/` here; see the category list in
[ARCHITECTURE.md §4](./ARCHITECTURE.md#4-repository-layout)). Per-category monoliths are
rejected, they're merge-conflict hotspots and defeat CODEOWNERS review routing.

### A.2 Write the pack

`rules/models/fireworks.yaml`, complete:

```yaml
# rules/models/fireworks.yaml
pack: fireworks
version: 1                       # informational; the CONTENT hash drives cache keys
rules:
  # Model IDs are quoted path literals: "accounts/fireworks/models/<model>".
  - id: fireworks/model-literal
    kind: hosted-llm
    provider: fireworks
    languages: [python, javascript, typescript, go, java, rust, csharp, kotlin]
    keywords: ["accounts/fireworks/models/"]       # Aho–Corasick prefilter — MANDATORY
    pattern: '["'']accounts/fireworks/models/(?P<model>[a-z0-9][\w.\-]*)["'']'
    regions: [code, string]                        # comments are never matched
    claim: { name: "${model}" }
    capture_params:                                # same-call-site binding (§9.5)
      within_lines: 12
      names: [temperature, top_p, top_k, max_tokens, seed, stop, response_format]
    confidence: 0.85

  # SDK usage: Python module import or the npm package specifier.
  - id: fireworks/sdk-import
    kind: library
    provider: fireworks
    languages: [python, javascript, typescript]
    keywords: ["fireworks.client", "fireworks-ai"]
    pattern: '(?:\bfrom\s+fireworks\.client\s+import\b|\bimport\s+fireworks\.client\b|["'']fireworks-ai["''])'
    regions: [code, string]                        # JS module specifiers are string regions
    claim: { name: "fireworks-ai" }
    confidence: 0.7
```

What each part does (full reference: [rule-schema.md](./rule-schema.md)):

- **`keywords`**, literal substrings fed into the single Aho–Corasick trie built over *all*
  packs at startup. Your regex never executes unless a keyword hits first. Keywords are
  **mandatory**: `airom rules lint` rejects keyword-less rules, so nobody can ship an
  un-prefiltered regex into a 100k-file scan.
- **`pattern`**, Go RE2 regex. Named groups (`(?P<model>…)`) become template variables and
  occurrence fields. Every named group must be referenced (lint-enforced).
- **`regions`**, the per-language region lexer classifies every file into code / string /
  comment regions before matching; comments are never scanned.
- **`claim`**, the templated component claim. `${model}` substitutes the named group. The
  assembler normalizes the raw name and mints identity. The rule never does.
- **`capture_params`**, captures listed kwarg-style bindings within 12 lines of the match
  into `Occurrence.Fields`. Because this occurrence carries a `model` binding, the assembler
  promotes them to provenance-carrying `BoundParam`s on the model's facet
  ([ARCHITECTURE.md §9.5](./ARCHITECTURE.md#95-ai-config--model-attachment-layered-refusal-first)).
- **`confidence`**, this sighting alone, in the range 0 < c ≤ 0.99. Corroboration across detection
  methods is the assembler's job (grouped noisy-OR, §9.3). Do not inflate.

Note what you did *not* write: no dedup logic (the same model ID in 40 files becomes one
component with 40 occurrences), no relationship to the `requirements.txt` entry for
`fireworks-ai` (the manifest detector finds that independently; the assembler's noisy-OR
corroborates across methods), no purl (derived by the assembler; hosted models get none by
design, §9.4).

### A.3 Write the fixtures

Every rule needs **at least one positive and one negative fixture case**, `airom rules
lint` fails the pack otherwise. Cases are marked with annotations the linter and golden
driver read (semgrep-style):

- `# airom: <rule-id>`, the next line (or this line, when trailing) **must** produce a
  finding for that rule.
- `# airom-ok: <rule-id>`: the next line **must not** produce a finding for that rule.

(Use the host language's comment syntax: `//` in TS, `#` in Python.)

`rules/models/testdata/fireworks/usage.py`:

```python
"""Fireworks AI usage fixture — positive and negative cases."""
import os

from fireworks.client import Fireworks  # airom: fireworks/sdk-import

client = Fireworks(api_key=os.environ["FIREWORKS_API_KEY"])


def ask(question: str) -> str:
    resp = client.chat.completions.create(
        # airom: fireworks/model-literal
        model="accounts/fireworks/models/llama-v3p1-70b-instruct",
        temperature=0.2,
        max_tokens=1024,
        messages=[{"role": "user", "content": question}],
    )
    return resp.choices[0].message.content


# Negative cases — no findings at or below this line.

# airom-ok: fireworks/model-literal
# model="accounts/fireworks/models/llama-v3p1-8b-instruct"   (comment region: never scanned)

# airom-ok: fireworks/sdk-import
DOCS = "see fireworks.client documentation for retry options"
```

`rules/models/testdata/fireworks/usage.ts`:

```ts
// Fireworks AI usage fixture — positive and negative cases.
import { Fireworks } from "fireworks-ai"; // airom: fireworks/sdk-import

const client = new Fireworks({ apiKey: process.env.FIREWORKS_API_KEY! });

export async function ask(question: string): Promise<string> {
  const resp = await client.chat.completions.create({
    // airom: fireworks/model-literal
    model: "accounts/fireworks/models/mixtral-8x22b-instruct",
    temperature: 0.1,
    max_tokens: 512,
    messages: [{ role: "user", content: question }],
  });
  return resp.choices[0].message?.content ?? "";
}

// Negative cases — no findings below this line.

// airom-ok: fireworks/model-literal
const assetPath = "accounts/fireworks/logo.png"; // no /models/ segment — keyword never fires

// airom-ok: fireworks/sdk-import
const note = "unrelated: a fireworks-display planner";
```

Good negatives are adversarial on purpose. The three above each exercise a different guard:
region gating (the commented-out model ID), keyword selectivity (`logo.png` never reaches
the regex), and regex precision (the docstring-ish sentence hits the `fireworks.client`
keyword but fails every pattern branch).

### A.4 The lint / test / golden loop

```console
$ airom rules lint rules/models/fireworks.yaml
$ go test ./rules/... -run Fireworks -update    # writes the golden
$ go test ./rules/... -run Fireworks            # green
```

> `airom rules lint` (and its no-Go-toolchain sibling `airom rules test <file>`) arrive with
> the CLI in **Phase 3**; the validation set is complete once the rule compiler lands in
> **Phase 5**. The `go test ./rules/...` pack driver, one subtest per pack, ships with the
> embedded packs in **Phase 6**. In CI all three run on every rules PR.

Lint checks (the full list lives in [rule-schema.md](./rule-schema.md#lint-contract)):
regexes compile, **keywords non-empty**, every named group referenced, every `${var}` backed
by a named group, IDs globally unique across all packs, ≥1 positive + ≥1 negative fixture
annotation per rule.

`-update` writes `rules/models/testdata/fireworks/findings.golden.json`, the exact findings
the pack produces over its fixtures. Excerpt (the `usage.py` entries):

```json
{
  "fixture": "usage.py",
  "findings": [
    {
      "claim": { "kind": "library", "provider": "fireworks", "name": "fireworks-ai" },
      "occurrence": {
        "detectorId": "rules/fireworks/sdk-import",
        "method": "source-code-analysis",
        "location": { "path": "usage.py", "line": 4 },
        "confidence": 0.7,
        "snippet": "from fireworks.client import Fireworks"
      }
    },
    {
      "claim": { "kind": "hosted-llm", "provider": "fireworks", "name": "llama-v3p1-70b-instruct" },
      "occurrence": {
        "detectorId": "rules/fireworks/model-literal",
        "method": "source-code-analysis",
        "location": { "path": "usage.py", "line": 12 },
        "confidence": 0.85,
        "snippet": "\"accounts/fireworks/models/llama-v3p1-70b-instruct\"",
        "fields": {
          "model": "llama-v3p1-70b-instruct",
          "temperature": "0.2",
          "max_tokens": "1024"
        }
      }
    }
  ]
}
```

Read your golden like a reviewer will: are the claims right, are the lines right, did
`capture_params` grab exactly the params on that call and nothing from elsewhere in the
file?

### A.5 See it run

```console
$ airom scan rules/models/testdata/fireworks -o table       # CLI lands in Phase 3
$ airom detectors explain rules/fireworks/model-literal     # capability-as-data view
$ airom scan . --rules rules/models/fireworks.yaml          # overlay onto any binary —
                                                            # useful before your PR merges
```

The last line matters operationally: anyone can adopt your pack **today** via the `--rules`
overlay, without waiting for a release. Merged packs are embedded (`go:embed`) into the next
release binary.

### A.6 What the PR contains

```
rules/models/fireworks.yaml                          (~35 lines of YAML)
rules/models/testdata/fireworks/usage.py
rules/models/testdata/fireworks/usage.ts
rules/models/testdata/fireworks/findings.golden.json
```

**1 YAML + 2 fixtures + 1 golden. Zero Go. Zero core changes.** CODEOWNERS routes it to the
rules maintainers; the review is "do the goldens look right." Cache correctness is
automatic, the SHA-256 of the effective compiled ruleset participates in every cache key,
so your pack self-invalidates every affected cache entry on merge
([rule-schema.md](./rule-schema.md#cache-keys)).

---

## Path B: a code detector, start to finish

We'll add a parser for **Keras v3 model archives** (`*.keras`), a ZIP container holding
`metadata.json` (Keras version), `config.json` (architecture), and the weights. Walking a
ZIP central directory is a loop over binary structures: firmly on the Go side of the bright
line.

### B.0 The interfaces you implement

Everything you need is in the public SDK, `pkg/airom/detect` (stdlib-only imports, semver-
guarded by apidiff in CI, lands in **Phase 5**):

```go
type Detector interface {
    ID() string        // stable, namespaced: "keras/v3"
    Version() int      // participates in cache keys; CI checks "detector diff ⇒ bump"
    Selector() Selector
}

// Phase 1 — one file at a time, streaming.
type FileDetector interface {
    Detector
    DetectFile(ctx context.Context, f *File) ([]Finding, error) // errors → Unknowns
}

// Phase 2 — cross-file, pull-style over a Resolver. Not covered in this walkthrough;
// the shape is DetectProject(ctx, resolver, priorFindings) and the same registration,
// harness, and PR mechanics apply.
type ProjectDetector interface { ... }
```

### B.1 Scaffold

```console
$ airom dev new-detector keras
created internal/detectors/keras/keras.go
created internal/detectors/keras/keras_test.go
created internal/detectors/keras/testdata/
```

> `airom dev new-detector` arrives with the CLI in **Phase 3**, templates in **Phase 6**.
> Same caveat as Path A; the files below are the whole scaffold.

Granularity rule: one detector = one *format or provider concern*. A new format gets its own
package under `internal/detectors/`; don't grow a mega-detector.

### B.2 Implement it

`internal/detectors/keras/keras.go`:

```go
// Package keras detects Keras v3 model archives (*.keras): a ZIP container
// with metadata.json, config.json, and model weights.
package keras

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// New returns the detector. No init() magic, no globals: the composition root
// (internal/app) wires every detector explicitly (§6.2).
func New() *Detector { return &Detector{} }

type Detector struct{}

func (*Detector) ID() string   { return "keras/v3" }
func (*Detector) Version() int { return 1 } // bump on ANY behavior change — CI enforces

func (*Detector) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".keras"},
		// ZIP local-file-header magic, checked against the shared 32 KB header
		// sample the walker already read — selection costs zero extra I/O.
		Magic:   []detect.Magic{{Offset: 0, Bytes: []byte{'P', 'K', 0x03, 0x04}}},
		MaxSize: 64 << 20, // we do a full-content parse; larger archives never reach us
		Need:    detect.NeedContent,
	}
}

type metadata struct {
	KerasVersion string `json:"keras_version"`
}
type config struct {
	ClassName string `json:"class_name"` // "Functional", "Sequential", …
}

func (d *Detector) DetectFile(ctx context.Context, f *detect.File) ([]detect.Finding, error) {
	data, err := f.Content() // THE single bounded, tee-hashed read (invariant P1)
	if err != nil {
		return nil, err // becomes an Unknown in the output; never kills the scan (P6)
	}

	// bytes.Reader over Content(), NOT f.ReaderAt(): ReaderAt returns
	// ErrNotSeekable on tar-stream sources (image scans). Content() is
	// source-agnostic — the harness's tar-backed run (B.4) enforces this.
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	var meta metadata
	var cfg config
	for _, zf := range zr.File {
		switch zf.Name {
		case "metadata.json":
			readJSON(zf, &meta)
		case "config.json":
			readJSON(zf, &cfg)
		}
	}
	if meta.KerasVersion == "" {
		return nil, nil // a ZIP named .keras that isn't a Keras archive: claim nothing
	}

	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind:     airom.KindLocalModelFile,
			Name:     f.Base(), // raw; the assembler normalizes — and weights-file
			//                     identity is the CONTENT HASH, not this name (§9.1)
			Provider: "local",
			Model: &detect.ModelClaim{
				Format:       "keras",
				Architecture: cfg.ClassName,
			},
		},
		Occurrence: airom.Occurrence{
			Location:   airom.Location{Path: f.Path()}, // Line 0 = whole file (§5)
			DetectorID: d.ID(),
			Method:     airom.MethodBinary,
			Confidence: 0.9, // magic + structural parse; 1.0 is reserved for
			//                  hash/attestation evidence (§9.3)
			Fields: map[string]string{"keras_version": meta.KerasVersion},
		},
	}}, nil
}

func readJSON(zf *zip.File, v any) {
	rc, err := zf.Open()
	if err != nil {
		return // partial metadata degrades the claim, not the scan
	}
	defer rc.Close()
	_ = json.NewDecoder(rc).Decode(v)
}
```

Exact `ComponentClaim`/`ModelClaim` field sets are authoritative in the `pkg/airom/detect`
godoc once Phase 5 lands; the shape above tracks
[ARCHITECTURE.md §6.1](./ARCHITECTURE.md#61-detector-interfaces-pkgairomdetect).

Things the engine does **for** you, so do not reimplement them:

- **Hashes.** Content is tee-hashed (xxh3 + SHA-256) during your one read; the assembled
  component gets `Hashes` for free, and content-hash identity dedups the same archive found
  at three paths into one component with three occurrences.
- **Panic containment.** A panic in `DetectFile` is recovered per file and recorded as an
  `Unknown` (with your detector ID and the path). The test harness, however, treats panics
  as failures, fix them there.
- **Selection.** Your `Selector()` is compiled into the global dispatch index. Never
  re-check extensions or magic inside `DetectFile`.

Two hard rules for parsers eating untrusted bytes (§13): return errors, never panic; never
allocate proportionally to an attacker-controlled length field. Binary parsers get fuzz
targets in CI (**Phase 8** wires the corpora). Write yours alongside the detector.

### B.3 Fixtures

```
internal/detectors/keras/testdata/
├── tiny.keras                 # handcrafted valid archive, a few hundred bytes:
│                              #   metadata.json + config.json, no weights
├── empty-zip.keras            # valid ZIP, no metadata.json → expect zero findings
├── decoy.txt                  # selector must gate this away from DetectFile
└── findings.golden.json       # written by -update
```

Handcraft the smallest valid input, exactly like the handcrafted GGUF headers in the core
fixture set (§14). Never commit real model weights.

### B.4 Test with the public harness

`internal/detectors/keras/keras_test.go`:

```go
package keras_test

import (
	"testing"

	"github.com/airomhq/airom/internal/detectors/keras"
	"github.com/airomhq/airom/pkg/airom/detectortest"
)

func TestKeras(t *testing.T) {
	detectortest.Run(t, keras.New(), detectortest.Fixtures{Dir: "testdata"})
}
```

`detectortest.Run` (public, third-party detectors use the identical harness; lands in
**Phase 5**) asserts, per its contract in
[ARCHITECTURE.md §14](./ARCHITECTURE.md#14-testing-strategy):

1. **Golden findings match** `testdata/findings.golden.json` (regenerate with
   `go test ./internal/detectors/keras -update`).
2. **`Selector()` actually gates.** Fixtures are routed through the real compiled dispatch
   index; the detector must see exactly the files its selector claims (`decoy.txt` reaching
   `DetectFile` is a failure), and every selector-matched fixture must reach it.
3. **Locations are 1-based** (0 = whole-file), columns are UTF-16 code units (decision D18).
4. **Determinism**: two runs produce identical findings (P7 at detector scope).
5. **No panic on truncated/empty input**: the harness auto-mutates every fixture (empty,
   1 byte, header-truncated) and requires an error or zero findings, never a panic.
6. **Both backings**: the entire suite runs twice, once dir-backed (where `ReaderAt`
   works) and once through an in-memory **tar-stream source** (where `ReaderAt` returns
   `ErrNotSeekable`). Seekability bugs die pre-merge instead of surfacing in image scans.

### B.5 Register it

Built-in detectors are cataloged in `internal/detectors/all/all.go`, which is **generated**:
there is no hand-edited central list for every PR to conflict on. Convention: your package
exports its constructor(s); the generator (ships in **Phase 5**) scans
`internal/detectors/*` and rewrites the list sorted by import path:

```console
$ go generate ./internal/detectors/all
```

```go
// Code generated by detectors-gen. DO NOT EDIT.
package all

func Builtin() []detect.Detector {
	return []detect.Detector{
		dataset.New(),
		gosrc.New(),
		infra.New(),
		keras.New(),        // ← appears after go generate
		manifest.New(),
		modelfile.NewGGUF(),
		// …
	}
}
```

Duplicate detector IDs **panic at startup**, CI runs the binary, so a collision fails the
PR rather than silently shadowing someone else's detector.

**Out-of-tree detectors:** library embedders pass their own detectors to the engine
constructor (the same explicit path. See `pkg/airom.Scan` options), so you can build and
ship a detector without forking AIROM. Out-of-*process* plugins are deliberately deferred
(v2, [ROADMAP.md](./ROADMAP.md)): the in-proc API must survive third-party use before a
wire protocol gets frozen.

### B.6 What the PR contains

```
internal/detectors/keras/keras.go
internal/detectors/keras/keras_test.go
internal/detectors/keras/testdata/tiny.keras
internal/detectors/keras/testdata/empty-zip.keras
internal/detectors/keras/testdata/decoy.txt
internal/detectors/keras/testdata/findings.golden.json
internal/detectors/all/all.go                      (regenerated, mechanical)
```

Follow-up changes to detector behavior must bump `Version()`, CI enforces "detector code
diff ⇒ version bump", which keeps the cache honest across releases.

---

## Command availability at a glance

| Command | Used for | Lands |
|---|---|---|
| `airom dev new-rulepack <name>` | Path A scaffold | Phase 3 (CLI) / Phase 6 (templates) |
| `airom dev new-detector <name>` | Path B scaffold | Phase 3 (CLI) / Phase 6 (templates) |
| `airom rules lint <file>` | pack validation | Phase 3 (CLI); full checks with the Phase 5 compiler |
| `airom rules test <file>` | run pack fixtures without a Go toolchain | Phase 3 / Phase 6 |
| `airom detectors list` / `explain <id>` | self-documenting capability view | Phase 3 |
| `go test ./rules/... [-update]` | pack golden driver | Phase 6 |
| `pkg/airom/detectortest.Run` | code-detector harness | Phase 5 |
| `airom scan … --rules <file>` | adopt an unmerged pack immediately | Phase 3 |

Until the marked phases land, the Go test drivers are the interface; nothing in either path
depends on unbuilt machinery to be *authored*, only to be *run*.

## Where to go next

- [rule-schema.md](./rule-schema.md), every rule-pack field, constraint, and the merge/
  compilation semantics.
- [cli.md](./cli.md), the full command surface these walkthroughs referenced.
- [ARCHITECTURE.md](./ARCHITECTURE.md), §6 (detector framework), §9 (what the assembler
  does with your claims), §14 (the test matrix your PR runs through).
