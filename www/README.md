# www — the airom.dev landing page

The static site served at **https://airom.dev**. The documentation is a separate
deployment at **https://docs.airom.dev** (built from [`../docs-site`](../docs-site)).

## Why they are two sites

Not preference — a constraint. `mint export` emits **absolute** asset paths
(`/_next/static/…`) and the Next.js runtime builds chunk URLs from an empty
`assetPrefix` that `mint export` gives no way to set. The docs therefore have to
be served from a **domain root**. Putting them at `airom.dev/docs` renders the
first page and then fails to load chunks, so the docs get their own subdomain and
the landing page gets the apex.

## What's here

| File | |
|---|---|
| `index.html` | The whole page. Inline CSS and JS, no build step, no dependencies. |
| `favicon.svg` | Kept in sync with `docs-site/favicon.svg`. |
| `og.png` | Social preview card, 1200×630. |
| `tools/make-og.py` | Regenerates `og.png`. Run it rather than hand-editing the PNG. |
| `vercel.json` | Headers and routing. |

## Editing

Open `index.html` in a browser — that is the whole development loop. There is
nothing to install and nothing to compile.

To regenerate the social card after changing the tagline or the mark:

```bash
python3 www/tools/make-og.py
```

## Self-contained on purpose

The page loads **nothing** from a third party: no CDN, no web fonts, no
analytics, no XHR. That is what lets `vercel.json` assert a
`Content-Security-Policy` of `default-src 'self'`, and it would be a poor look
for a tool whose pitch includes "no surprise network access" to ship a marketing
page that phones home.

`'unsafe-inline'` is in the policy for `script-src` and `style-src` because both
are inline by design: it saves a stylesheet round-trip, and the theme script
*must* run before first paint or the page flashes the wrong colours on reload.

## Facts on this page

Counts and claims are pulled from the tool, not written from memory. If you
change one, re-derive it:

```bash
airom rules list | tail -1        # rule count
airom detectors list | tail -n +2 | wc -l   # detector count
```

Everything else mirrors the root `README.md` and `docs/project-status.md`. When
those change, this page is not updated automatically — check it.
