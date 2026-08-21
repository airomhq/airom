// Package fix turns the CVE overlay into an actionable remediation: for every
// vulnerable package it computes the version that clears the advisories and
// rewrites the pin in the manifest that declared it.
//
// Three rules govern everything here:
//
//  1. **Declared sources only.** A lockfile, an installed-metadata directory,
//     or a frozen binary records what a resolver already decided; editing one
//     forges a resolution nobody computed. Only the manifest a human wrote is
//     rewritten, and a stale lockfile is reported rather than patched.
//
//  2. **Prove the edit before making it.** A Target is applied only when the
//     line it points at still contains the package name and the exact version
//     the scan saw. If the file moved on since the scan, the fix refuses
//     instead of rewriting the wrong bytes.
//
//  3. **One version per package.** Advisories fix on different lines
//     (`0.1.0` for one CVE, `0.2.4` for another); the remediation is the
//     highest of them, applied once, not a sequence of partial bumps.
//
// The package is pure logic with a filesystem tail: Plan is a function of the
// Inventory alone and Apply touches exactly one file. The interactive table
// lives in internal/fix/fixui, which consumes this and nothing else.
package fix
