// Package rulesync fetches, verifies, and caches a signed rule-pack bundle from
// the airomhq/airom-rules release channel, so rules can move faster than the
// airom binary without the user installing a second tool (Model B).
//
// Trust model. A bundle is a gzipped tar of the YAML packs plus a manifest.json
// (version, tarball SHA-256, counts) and a detached ed25519 signature over the
// manifest bytes. airom verifies the signature against a public key embedded in
// the binary, then checks the tarball's SHA-256 against the manifest, then
// extracts. Any failure is fatal — a bundle is never partially trusted. The
// only escape hatch is an explicit InsecureSkipSignature.
//
// Determinism and offline. Fetching happens on an explicit `airom rules
// update`, and — when the caller enables it — through AutoUpdate before a scan
// resolves its rules. AutoUpdate is throttled to at most one check a day, is
// skipped entirely under Offline or in a CI environment, and treats every
// network failure as "keep what we have", so a scan can never fail because a
// rules server was unreachable. Update refuses before dialing when Offline is
// set, mirroring the git source. The embedded packs remain the offline floor; a
// cached bundle is an override, and `--rules` overlays still layer on top of
// whichever wins.
//
// Auto-update trades reproducibility for freshness, which is why it stands down
// in CI: two scans of one commit must agree, `airom diff` refuses across a
// ruleset change by design, and a --fail-on gate that flips with no commit
// behind it is a broken build rather than a finding. When it does install
// something, the scan says so in the document, not only on stderr.
//
// This package holds airom's only outbound fetch besides the OSV overlay and
// its first crypto verification; it lives in internal/ so pkg/airom stays
// stdlib-only.
package rulesync
