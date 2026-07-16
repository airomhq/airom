package manifest

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"strings"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// CSProj detects AI dependencies declared as <PackageReference> entries in a
// .NET project file (*.csproj).
type CSProj struct{}

// NewCSProj constructs the .csproj detector.
func NewCSProj() *CSProj { return &CSProj{} }

// ID is the stable detector identity.
func (CSProj) ID() string { return "manifest/nuget" }

// Version participates in cache keys; bump on any behavior change.
func (CSProj) Version() int { return 1 }

// Selector routes *.csproj files by extension, needing full content.
func (CSProj) Selector() detect.Selector {
	return detect.Selector{
		Extensions: []string{".csproj"},
		MaxSize:    8 << 20,
		Need:       detect.NeedContent,
	}
}

// DetectFile streams the project XML, reading each <PackageReference>'s
// Include/Version (attribute or child element) and matching against the NuGet
// catalog. Malformed input yields what was gathered — never a panic.
func (d CSProj) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err
	}
	dec := xml.NewDecoder(bytes.NewReader(content))
	var out []detect.Finding
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, nil
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "PackageReference" {
			continue
		}
		off := dec.InputOffset()
		var ref struct {
			Include     string `xml:"Include,attr"`
			VersionAttr string `xml:"Version,attr"`
			VersionElem string `xml:"Version"`
		}
		if err := dec.DecodeElement(&ref, &se); err != nil {
			return out, nil
		}
		name := strings.TrimSpace(ref.Include)
		if name == "" {
			continue
		}
		p, matched := nugetCatalog.lookup(strings.ToLower(name))
		if !matched {
			continue
		}
		version := ref.VersionAttr
		if version == "" {
			version = ref.VersionElem
		}
		out = append(out, mkFinding(p, p.emitName(name), "", "nuget", strings.TrimSpace(version), lineAt(content, off)))
	}
	return out, nil
}
