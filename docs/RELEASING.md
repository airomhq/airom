# Releasing AIROM

Written down because the version now lives in **two repositories**. Before the
web split, `make` and a single `git push` covered everything; now a release that
updates only this repo ships a documentation site advertising the previous
version, and nothing fails to tell you.

## The version appears in five places

Four here, one in [airomhq/airom-web](https://github.com/airomhq/airom-web):

| Repo | File | Form |
|---|---|---|
| airom | `sdk/python/src/airom/__init__.py` | `__version__ = "<version>"` |
| airom | `sdk/python/README.md` | `airom <version>` |
| airom | `README.md` | `**v<version>**, early but real.` |
| airom | `docs/project-status.md` | `AIROM is at **v<version>**` |
| **airom-web** | `docs-site/installation.mdx` | **four times**: see below |

The four in `installation.mdx` are the callout, `@latest resolves to…`, the
`airom version` sample output under the pip/pipx tab (which carries a commit
and build date too, so bump those to the real ones or the block contradicts
itself), and the `git describe` example under `make build`. Grep, do not count
from memory:

```bash
grep -n "<previous version>" docs-site/installation.mdx
```

Not the Go binary: its version comes from the tag at build time via ldflags
(see the `LDFLAGS` block in the `Makefile`), so there is no version constant to
edit in Go.

Historical mentions of an older version in prose are **not** bumped. That covers
`docs/mapping.md` explaining why the SPDX namespace changed in v0.3.7, release
notes, and changelog entries. They describe what a specific version did.

## Checklist

1. **Land the work.** `main` green, everything merged.

2. **Bump the four files in this repo.** Verify nothing was missed:

   ```bash
   grep -rn "<previous version>" --include="*.md" --include="*.py" . | grep -v "^./.git/"
   ```

   Read each hit. Anything left should be deliberate history, not an oversight.

3. **Bump `docs-site/installation.mdx` in airom-web**, both occurrences, and
   push. This is the step the split made easy to forget.

4. **Full sweep here.**

   ```bash
   golangci-lint run && go test ./... -race
   ```

5. **Commit and push.** The push publishes the Python SDK to PyPI. Every wheel is
   installed and run on the platform it targets first (the `smoke` jobs in
   `release-pypi.yml`), so a cross-compiled binary that does not execute fails
   before publication rather than after. PyPI never lets a version be
   re-uploaded, so that gate is the only chance to catch it. Confirm:

   ```bash
   curl -s https://pypi.org/pypi/airom/json | python3 -c "import json,sys;print(json.load(sys.stdin)['info']['version'])"
   ```

6. **Tag.** Use an annotated tag; its message becomes the human half of the
   release, since the GitHub release body is goreleaser's generated changelog.
   Say what changed and, explicitly, what upgrading costs.

   ```bash
   git tag -a v<version> -m "..." && git push origin v<version>
   ```

7. **Verify what actually shipped.** Not that the workflow went green, but
   that the artifact is right:

   ```bash
   gh run list --workflow Release --limit 1
   gh release view v<version> --json assets --jq '.assets[].name'

   # Download one binary, check it against the published checksum, and run it.
   gh release download v<version> -p 'airom_*_darwin_arm64.tar.gz' -p 'checksums.txt'
   grep -E "darwin_arm64.tar.gz$" checksums.txt | awk '{print $1}' \
     | diff - <(shasum -a 256 airom_*_darwin_arm64.tar.gz | awk '{print $1}')
   tar xzf airom_*_darwin_arm64.tar.gz && ./airom --version
   ```

8. **Exercise the headline change with the downloaded binary**, not a local
   build. A local build can pass while the released artifact is broken.

## Rule bundles release separately

[airomhq/airom-rules](https://github.com/airomhq/airom-rules) has its own
version and its own cadence. Rule and lifecycle-catalog changes reach users
through the signed update channel without a new scanner release. That is the
point of the channel. Only bump the scanner when scanner code changed.

One exception, because it has caught us out: **packaging changes need a bump
even when no scanner code moved.** The wheel matrix runs only when the version
in `sdk/python/src/airom/__init__.py` is not already on PyPI, so a new wheel
platform reaches nobody until a release ships it. v0.3.8 was exactly this: no
Go code changed, and the release existed to publish the Windows arm64 wheel.
Say so in the tag message, so a reader can tell an optional upgrade from a
behavioural one.
