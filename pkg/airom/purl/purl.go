// Package purl builds package URLs under AIROM's purl discipline
// (ARCHITECTURE.md §9.4, decision D9): spec purl types only. Hosted API
// models get NO purl — identity travels as bom-ref plus airom:model.*
// properties — because fabricating pkg:generic/openai/gpt-4.1 pollutes
// every purl-keyed consumer (Dependency-Track). Weights files use
// pkg:generic with a checksum qualifier; packages use their ecosystem type.
package purl

import (
	"fmt"
	"net/url"
	"strings"
)

// Generic returns the purl for a bare weights file:
// pkg:generic/<name>?checksum=sha256:<hex>. The checksum qualifier is what
// makes it meaningful — a name alone identifies nothing.
func Generic(name, sha256hex string) string {
	if name == "" || sha256hex == "" {
		return ""
	}
	return "pkg:generic/" + encodeSegment(name) + "?checksum=sha256:" + strings.ToLower(sha256hex)
}

// HuggingFace returns pkg:huggingface/<namespace>/<name>[@revision].
// Namespace and name are lowercased per the purl-type definition.
func HuggingFace(namespace, name, revision string) string {
	if namespace == "" || name == "" {
		return ""
	}
	p := "pkg:huggingface/" + encodeSegment(strings.ToLower(namespace)) + "/" + encodeSegment(strings.ToLower(name))
	if revision != "" {
		p += "@" + encodeSegment(revision)
	}
	return p
}

// OCI returns pkg:oci/<name>@<digest> for container images.
func OCI(name, digest string) string {
	if name == "" {
		return ""
	}
	p := "pkg:oci/" + encodeSegment(strings.ToLower(name))
	if digest != "" {
		p += "@" + encodeSegment(digest)
	}
	return p
}

// ecosystems maps AIROM ecosystem slugs to purl types with their
// normalization rules.
var ecosystems = map[string]struct {
	typ            string
	lowerNamespace bool
	lowerName      bool
	pypiName       bool // PEP 503: lowercase, runs of -_. collapse to -
}{
	"pypi":   {typ: "pypi", lowerName: true, pypiName: true},
	"npm":    {typ: "npm", lowerNamespace: true, lowerName: true},
	"golang": {typ: "golang", lowerNamespace: true, lowerName: true},
	"maven":  {typ: "maven"},
	"cargo":  {typ: "cargo"},
	"nuget":  {typ: "nuget"},
}

// Package returns the ecosystem purl for a framework/library dependency,
// or an error for an unknown ecosystem.
func Package(ecosystem, namespace, name, version string) (string, error) {
	rules, ok := ecosystems[strings.ToLower(ecosystem)]
	if !ok {
		return "", fmt.Errorf("purl: unknown ecosystem %q", ecosystem)
	}
	if name == "" {
		return "", fmt.Errorf("purl: empty package name")
	}
	if rules.lowerNamespace {
		namespace = strings.ToLower(namespace)
	}
	if rules.lowerName {
		name = strings.ToLower(name)
	}
	if rules.pypiName {
		name = normalizePyPI(name)
	}
	p := "pkg:" + rules.typ + "/"
	if namespace != "" {
		p += encodeSegment(namespace) + "/"
	}
	p += encodeSegment(name)
	if version != "" {
		p += "@" + encodeSegment(version)
	}
	return p, nil
}

// NormalizePyPI applies PEP 503 name normalization: lowercase, with runs of
// '-', '_', '.' collapsed to a single '-'. Exported because the assembler's
// package normalizer chain uses the same rule (§9.1).
func NormalizePyPI(name string) string { return normalizePyPI(strings.ToLower(name)) }

func normalizePyPI(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	prevDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
			}
			prevDash = true
			continue
		}
		prevDash = false
		b.WriteRune(r)
	}
	return b.String()
}

// encodeSegment percent-encodes one purl path segment, splitting on '/' so
// namespaces like github.com/acme survive as path structure.
func encodeSegment(s string) string {
	parts := strings.Split(s, "/")
	for i, p := range parts {
		// url.PathEscape matches the purl spec's separator handling (it leaves
		// ':' ',' ';' literal, as OCI digests and the spec require), but the
		// spec additionally requires '@' -> %40 and '+' -> %2B, which
		// PathEscape leaves literal. Without this an npm scope (@anthropic-ai)
		// or a semver build version (1.0.0+build) yields a non-canonical purl
		// that a strict consumer (Dependency-Track) re-canonicalizes, so the
		// component fails to dedup by purl. (Phase 10 review, api-cli-config.)
		e := url.PathEscape(p)
		e = strings.ReplaceAll(e, "@", "%40")
		e = strings.ReplaceAll(e, "+", "%2B")
		parts[i] = e
	}
	return strings.Join(parts, "/")
}
