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

// Maven detects AI dependencies declared in a Maven pom.xml.
type Maven struct{}

// NewMaven constructs the Maven pom.xml detector.
func NewMaven() *Maven { return &Maven{} }

// ID is the stable detector identity.
func (Maven) ID() string { return "manifest/maven" }

// Version participates in cache keys; bump on any behavior change.
func (Maven) Version() int { return 1 }

// Selector routes pom.xml files, needing full content.
func (Maven) Selector() detect.Selector {
	return detect.Selector{
		Basenames: []string{"pom.xml"},
		MaxSize:   8 << 20,
		Need:      detect.NeedContent,
	}
}

// DetectFile streams the XML, decoding each <dependency> element and mapping
// its start offset to a 1-based line. Malformed input yields the findings
// gathered so far — never a panic.
func (d Maven) DetectFile(_ context.Context, f *detect.File) ([]detect.Finding, error) {
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
			return out, nil // best-effort on malformed/truncated XML
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "dependency" {
			continue
		}
		off := dec.InputOffset()
		var dep struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		}
		if err := dec.DecodeElement(&dep, &se); err != nil {
			return out, nil
		}
		group := strings.TrimSpace(dep.GroupID)
		artifact := strings.TrimSpace(dep.ArtifactID)
		p, ok := mavenLookup(group, artifact)
		if !ok {
			continue
		}
		out = append(out, mkFinding(p, p.emitName(artifact), group, "maven", mavenVersion(dep.Version), lineAt(content, off)))
	}
	return out, nil
}

// mavenVersion trims the declared version, dropping unresolved property
// placeholders like "${langchain4j.version}".
func mavenVersion(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "${") {
		return ""
	}
	return v
}

// lineAt converts a byte offset into a 1-based line number.
func lineAt(content []byte, off int64) int {
	if off > int64(len(content)) {
		off = int64(len(content))
	}
	return 1 + bytes.Count(content[:off], []byte{'\n'})
}
