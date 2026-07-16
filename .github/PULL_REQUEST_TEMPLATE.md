<!--
Thanks for contributing to AIROM. Keep PRs focused; a small, reviewable
change with tests lands faster than a large one.
-->

## What & why

<!-- What does this change and why? Link the issue: Closes #123 -->

## Type of change

- [ ] Bug fix (no API change)
- [ ] New detector / rule pack
- [ ] New source or output format
- [ ] Refactor / internal
- [ ] Docs only

## Checklist

- [ ] `make test` passes (the suite runs under `-race`).
- [ ] `make lint` is clean (includes the import-direction depguard rules).
- [ ] `go generate ./...` produces no diff (regenerated `internal/detectors/all` if I added a detector).
- [ ] I added or updated tests for the behavior I changed.
- [ ] Golden files are re-recorded intentionally, and I reviewed the diff (if output changed).
- [ ] Docs updated (`docs/`, `README.md`) if behavior or flags changed.

## For new detectors

<!-- Delete if not applicable. -->

- [ ] One rule per detector, evidence-keyed (file names / imports / config keys).
- [ ] Fixture with inline annotations under the pack's `testdata/`.
- [ ] Field mapping follows `docs/mapping.md` (no new `airom:*` property without documenting it).

## Notes for reviewers

<!-- Anything non-obvious: trade-offs, follow-ups, things you're unsure about. -->
