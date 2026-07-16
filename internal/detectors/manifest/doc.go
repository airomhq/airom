// Package manifest detects AI frameworks and SDKs declared in package
// manifests and lockfiles (ARCHITECTURE.md §4, §17): requirements.txt,
// pyproject.toml, package.json, go.mod, pom.xml, Gradle lockfiles,
// Cargo.toml, and csproj, emitting framework and library claims with
// declared versions.
//
// AIROM needs presence and version, not dependency resolution (decision
// D13): every format is parsed with the standard library plus
// golang.org/x/mod for go.mod, matched against a curated AI-package
// knowledge table (catalog.go) so ordinary web/build dependencies are never
// emitted. Each ecosystem has its own zero-arg constructor and stable
// detector ID (manifest/pypi-requirements, manifest/npm, …). Manifest
// evidence later joins lockfile evidence in the phase-2 lockjoin detector
// (internal/detectors/project) and corroborates rule-pack usage findings in
// the assembler.
package manifest
