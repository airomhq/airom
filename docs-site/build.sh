#!/usr/bin/env bash
# Build the static documentation site into ./dist.
#
# Used by Vercel (see vercel.json) and runnable locally. Four things about this
# are not obvious:
#
#   1. `mint export` can ONLY write a zip — there is no --output-dir. So the
#      build exports and then unpacks. The zip's contents are already rooted
#      correctly (index.html, _next/, concepts/, …), so it unpacks straight
#      into dist.
#
#   2. `mint export` sweeps unrecognized files in the project root into the
#      bundle as static assets. A build script and a previous export.zip left
#      lying here both end up INSIDE the published site — and a stale dist/
#      would get swallowed whole, compounding on every run. So the export goes
#      to a temp path outside the tree, dist/ is removed before the export runs
#      rather than after, and anything that leaks through is stripped and then
#      asserted gone. Silence here means shipping a 50 MB zip of the site
#      inside the site.
#
#   3. The export hardcodes ABSOLUTE asset paths (/_next/static/…) and the
#      Next.js runtime builds chunk URLs from an empty assetPrefix that `mint
#      export` gives no way to set. The site therefore MUST be served from a
#      domain root. docs.airom.dev is one. A project path like example.com/docs
#      renders the first page and then fails to load chunks.
#
#   4. Mintlify refuses to run on Node 25+. package.json pins engines.node to
#      24.x so this does not silently break the day a build image's default
#      moves on; the check below turns that into a legible error either way.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

command -v unzip >/dev/null || { echo "error: unzip is required" >&2; exit 1; }

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$node_major" -ge 25 ]; then
  echo "error: mintlify does not support Node ${node_major}; pin to 24.x (see package.json engines)" >&2
  exit 1
fi

# Out of the source tree, so the export cannot swallow its own output.
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
zip="$workdir/export.zip"

# Before, not after: a leftover dist/ present during the export gets bundled.
rm -rf dist export.zip

echo "==> exporting with mint (Node $(node -v))"
npx --yes mint@latest export --output "$zip"

echo "==> unpacking into dist/"
mkdir -p dist
unzip -q "$zip" -d dist

# Project files that mint copied in as if they were site assets, plus the
# local-preview helpers it ships. All inert on a static host; none of them
# belong in a published site.
rm -rf dist/dist
rm -f dist/build.sh dist/export.zip dist/vercel.json dist/package.json \
      dist/package-lock.json dist/README.md \
      dist/serve.js "dist/Start Docs.command" "dist/Start Docs.bat"
# Every dotfile at the site root. The first deploy published .vercelignore
# because the guard below named .git* specifically and nothing else — a
# denylist of exact names is only ever as complete as the last thing that got
# caught. A dotfile at the root of a static site is never something Mintlify
# meant to publish, so match the shape instead of the name.
find dist -maxdepth 1 -name '.*' ! -name '.' -exec rm -rf {} +

# Assert it, rather than trusting the removals above to stay complete: if a
# future mint version sweeps in something new, this fails the build instead of
# publishing it.
leaked=$(find dist -maxdepth 1 \( -name "*.sh" -o -name "*.zip" -o -name "vercel.json" \
  -o -name "package*.json" -o -name ".*" ! -name "." \) -print)
if [ -n "$leaked" ]; then
  echo "error: project files leaked into the published site:" >&2
  echo "$leaked" >&2
  exit 1
fi

test -f dist/index.html || { echo "error: dist/index.html missing — the export did not produce a site" >&2; exit 1; }

echo "==> built $(find dist -type f | wc -l | tr -d ' ') files into dist/"
