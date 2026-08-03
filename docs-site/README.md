# AIROM documentation site

The user-facing documentation for AIROM, built with [Mintlify](https://mintlify.com).

> **Not hosted anywhere yet.** These pages render as source on GitHub and build
> cleanly in CI; picking a host is the only step left. See
> [Publishing it](#publishing-it) below — the constraints there were established
> by trying it, so they should not need rediscovering.

- **Config:** [`docs.json`](docs.json) — theme, colors, and the navigation tree.
- **Pages:** `.mdx` files, grouped by section (`concepts/`, `scanning/`, `output/`,
  `ci/`, `rules/`, `reference/`). Every page in `docs.json` must exist, and every
  `.mdx` file should be reachable from the navigation.

## Preview locally

> **Node must be an LTS release.** Mintlify refuses to run on odd/current Node
> majors — on Node 25+ it exits with
> `mintlify is not supported on node versions 25+ … Please downgrade to an LTS
> node version`. Use an Active LTS (Node 24 or 22).

```bash
# If your default node is non-LTS (check with `node --version`), install an LTS
# alongside it. Homebrew's node@24 is keg-only, so it does not replace your node:
brew install node@24
export PATH="/opt/homebrew/opt/node@24/bin:$PATH"   # Apple Silicon
# export PATH="/usr/local/opt/node@24/bin:$PATH"    # Intel
node --version                                      # expect v24.x

cd docs-site
npx mint dev       # serves http://localhost:3000
```

From the repo root, three shortcuts wrap the same tooling:

```bash
make docs          # local preview with hot reload
make docs-check    # strict validation + link check (what CI runs)
make docs-export   # static bundle → docs-site/export.zip (gitignored)
```

## CI

[`.github/workflows/docs.yml`](../.github/workflows/docs.yml) validates, checks
links, and exports on every change under `docs-site/`, uploading the static
bundle as a build artifact. It publishes nothing.

## Publishing it

**The site must be served from a domain ROOT.** `mint export` writes absolute
asset paths (`/_next/…`), and the Next.js runtime builds chunk URLs from an
`assetPrefix` that the export gives no option to set — 15 of the emitted JS
chunks embed `assetPrefix+"/_next/"`. Served from a subpath, the first page
renders and everything after it fails to load, which reads as a broken site
rather than a misconfigured one. Rewriting the HTML does not fix it; the runtime
construction defeats that.

So a **project** Pages path (`https://airomhq.github.io/airom/`) is not viable.
Three targets are:

| Target | URL | What it needs |
| --- | --- | --- |
| Org GitHub Pages | `https://airomhq.github.io/` | A public repo named `airomhq.github.io`, plus a step in the docs workflow to push the unzipped export there. Free; the org has no Pages site today. |
| Custom domain | e.g. `https://airom.dev/` | Registering the domain (it had no NS records when checked) and pointing DNS at the host. Note `docs/mapping.md` uses `airom.dev` as an SPDX namespace IRI — an IRI is an identifier and never has to resolve, so that reference implies nothing about ownership. |
| Mintlify hosted | their subdomain, or a custom one | An account with the repo connected in their dashboard. This is what `docs.json` is designed for, and brings search, analytics, and per-PR previews. No repo changes needed. |

Whichever is chosen, switch the root README's documentation links from repo
paths to the published URLs at the same time.

Prefer a version manager for this? `brew install fnm`, then `fnm install --lts &&
fnm use lts-latest`.

## Relationship to `docs/`

This directory is the **user-facing documentation site**. The repository's
[`docs/`](../docs) directory is the **engineering reference** — `ARCHITECTURE.md`
(the canonical design and decision log), `mapping.md` (the authoritative
field-mapping law), `cli.md`, and `rule-schema.md`. Those are linked from source
comments and are deliberately kept as plain Markdown; this site links out to them
rather than duplicating them.

## The accuracy rule

Every flag, command, and output shape documented here **must exist in the shipped
binary**. A prior review found four docs-vs-code divergences (a phantom `-v`
behavior, a phantom table column, a wrong rule-pack count), so when changing the
CLI, update these pages in the same commit. The fastest ground truth is the binary
itself:

```bash
make build && ./airom --help && ./airom <command> --help
```

Be equally honest about what does *not* work yet — pre-release status, the
intentionally empty CycloneDX `dependencies[]`, and the unwired live
registry/daemon and Kubernetes cluster modes.
