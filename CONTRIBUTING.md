# Contributing to AIROM

Thanks for your interest in AIROM — the AIBOM scanner for AI assets. This guide
covers how to get set up, the conventions we hold to, and the most common
contribution: adding a detector.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting set up

You need **Go 1.26+**. Everything else is a `make` target.

```sh
git clone https://github.com/Roro1727/airom
cd airom
make build      # static binary at ./airom (CGO_ENABLED=0)
make test       # full suite under the race detector
make lint       # golangci-lint (config: .golangci.yml)
make help       # list every target
```

There is no CGO and no external toolchain — a clean Go install is enough.

## The design in one paragraph

AIROM reads untrusted inputs once, decides what to parse before reading, and
emits **claims about evidence** — never bare components. The full design,
including the eight invariants (P1–P8) and the field-mapping law, lives in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/mapping.md`](docs/mapping.md). Read `ARCHITECTURE.md` §1–§6 before making
anything more than a small fix; it will save you a review round.

A few load-bearing rules a linter can't fully catch:

- **Import direction (§4).** `pkg/airom` is the public core and imports nothing
  from `internal/`. `pkg/airom` and `pkg/airom/detect` stay standard-library
  only. The `depguard` rules in `.golangci.yml` enforce this — if `make lint`
  complains about an import, that's the law talking, not a nit.
- **Writers are pure (P5).** Output writers transform an `Inventory` into bytes
  with no I/O or clock access. Determinism (P7) is tested with golden files.
- **Bounded, read-once, degradable (P1–P3, P6).** A hostile input must not
  crash the scan or exhaust memory; a detector that fails degrades the result,
  it doesn't abort the run.

## Adding a detector

This is the path most contributions take. Detectors are **declarative rule
packs**, not hand-written Go — one rule per detector, keyed on evidence.

1. **Identify the evidence.** What unambiguously signals this asset? File names
   or extensions, import/package paths, config keys, magic bytes. If you can't
   name concrete evidence, it isn't ready to be a detector yet.
2. **Write the rule pack** under the appropriate rules directory as YAML. Follow
   an existing pack of the same shape as a template; keep it to one detector.
3. **Add a fixture** with inline annotations under the pack's `testdata/`. The
   fixture is both the example and the test — it asserts what the detector
   claims and at what confidence.
4. **Register it:** `go generate ./...` regenerates
   `internal/detectors/all`. Commit the regenerated file; CI fails if it's
   stale.
5. **Map the output.** Any field you emit must follow
   [`docs/mapping.md`](docs/mapping.md). Don't invent a new `airom:*` property
   without documenting it there.
6. `make test && make lint`, then open the PR.

For new **sources** (image, k8s, …) or **output formats**, open an issue first
so we can agree on the shape — those touch shared seams.

## Testing

- Everything runs under `-race` (`make test`). New concurrency must be
  race-clean.
- Output changes are golden-tested. Re-record intentionally with
  `make golden`, then **review the diff** before committing — an unreviewed
  golden update defeats the test.
- Parsers of untrusted bytes must have a `Fuzz*` target. Run `make fuzz`
  locally; new crashers get minimized into `testdata/fuzz/` and committed as
  regression seeds.
- Aim to cover the behavior you changed, not to hit a coverage number.

## Commits & pull requests

- We use [Conventional Commits](https://www.conventionalcommits.org):
  `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. The scope is
  optional (`feat(detect): …`). The changelog is generated from these.
- Keep PRs focused and reviewable. A small change with tests lands faster than a
  sprawling one.
- Fill out the PR checklist honestly — it's the same gate CI runs.
- Rebase on `main` rather than merging it back in; keep history linear.

## Reporting bugs & vulnerabilities

- Functional bugs: open an issue with the input (or a minimized version) and the
  output. See the bug template.
- **Security issues: do not open a public issue.** Follow
  [SECURITY.md](SECURITY.md) — private advisory or email.

## License

AIROM is MIT-licensed. By contributing, you agree that your contributions are
licensed under the same terms.
