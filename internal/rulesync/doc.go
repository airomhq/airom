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
// Determinism and offline. Fetching happens ONLY on an explicit `airom rules
// update`; a scan never reaches the network and always uses whatever bundle is
// already cached (or the embedded packs). Update refuses before dialing when
// Offline is set, mirroring the git source. The embedded packs remain the
// offline floor; a cached bundle is an override, and `--rules` overlays still
// layer on top of whichever wins.
//
// This package holds airom's only outbound fetch besides the OSV overlay and
// its first crypto verification; it lives in internal/ so pkg/airom stays
// stdlib-only.
package rulesync
