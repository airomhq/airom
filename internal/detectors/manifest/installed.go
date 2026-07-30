package manifest

import (
	"context"
	"path"
	"strings"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// confInstalled is the per-sighting confidence for installed metadata. It sits
// above confDeclared because the two claims differ in kind: requirements.txt
// says which version was ASKED FOR ("openai>=1.0"), while a dist-info directory
// says which one is THERE. Scanning a container or a frozen bundle is the one
// case where the resolved answer is on disk. Still short of 1.0, which the
// assembler reserves for hash and attestation evidence.
const confInstalled = airom.Confidence(0.97)

// Installed detects AI dependencies from Python INSTALLED-package metadata —
// `<pkg>-<ver>.dist-info/METADATA` (PEP 376) and `<pkg>.egg-info/PKG-INFO` —
// rather than from a source-tree manifest.
//
// This is what makes a deployed environment scannable. A container's
// site-packages, a venv, or an unpacked PyInstaller bundle carries no
// requirements.txt, so every component came back version-less: scanning an
// extracted bundle reported openai and langchain with no version at all, while
// the exact versions sat unread in the sibling `litellm-1.79.0.dist-info/`.
//
// It does NOT turn AIROM into a general SBOM tool. The same curated AI catalog
// the source manifests use gates every claim, so an installed tree of 84
// packages yields the handful that are AI — not numpy, click, and attrs.
//
// Scope follows from the default ignores rather than a flag: `.venv/`,
// `venv/`, and `node_modules/` are skipped, so a project scan never sees its
// own dependency tree here (it has a manifest for that). Point AIROM at an
// installed environment and the metadata is simply visible.
type Installed struct{}

// NewInstalled constructs the installed-metadata detector.
func NewInstalled() *Installed { return &Installed{} }

// ID is the stable detector identity.
func (Installed) ID() string { return "manifest/pypi-installed" }

// Version participates in cache keys; bump on any behavior change.
func (Installed) Version() int { return 1 }

// Selector routes the two metadata filenames. Both are small headers followed
// by a long description, so the cap is well under the manifest default.
func (Installed) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"METADATA", "PKG-INFO"},
		MaxSize:   1 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile reads the Name and Version headers of one metadata file.
func (d Installed) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	// "METADATA" and "PKG-INFO" are ordinary words; only their placement makes
	// them package metadata. Without this, any file so named — a fixture, a
	// data dictionary — would be parsed as an installed package.
	if !isInstalledMetadataDir(path.Dir(f.Path())) {
		return nil, nil
	}
	content, err := f.Content()
	if err != nil {
		return nil, err
	}

	name, version, line := parseMetadataHeaders(content)
	if name == "" {
		return nil, nil
	}
	key := normalizePyPI(name)
	p, ok := pypiCatalog.lookup(key)
	if !ok {
		return nil, nil // installed, but not AI — not this tool's business
	}
	fnd := mkFinding(p, p.emitName(key), "", "pypi", version, line)
	fnd.Occurrence.Confidence = confInstalled
	return []detect.Finding{fnd}, nil
}

// isInstalledMetadataDir reports whether a directory is a PEP 376 dist-info or
// a setuptools egg-info tree.
func isInstalledMetadataDir(dir string) bool {
	base := path.Base(dir)
	return strings.HasSuffix(base, ".dist-info") || strings.HasSuffix(base, ".egg-info")
}

// parseMetadataHeaders reads the RFC 822 header block, returning the Name,
// Version, and the 1-based line the Name appeared on.
//
// It stops at the first blank line. Everything after that is the long
// description — often the entire README, which may quote a "Name:" of its own
// and would otherwise overwrite the real one.
func parseMetadataHeaders(content []byte) (name, version string, line int) {
	for i, raw := range splitLines(content) {
		l := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(l) == "" {
			break // end of headers
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue // a folded continuation of the previous header
		}
		key, value, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		// First occurrence wins for each: a well-formed file has one of each,
		// and a malformed one should not have its identity rewritten late.
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			if name == "" {
				name, line = value, i+1
			}
		case "version":
			if version == "" {
				version = value
			}
		}
		if name != "" && version != "" {
			break
		}
	}
	return name, version, line
}
