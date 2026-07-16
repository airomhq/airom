package cli

import (
	"fmt"
	"strings"
	"unicode"
)

func rulepackTemplate(name string) string {
	return fmt.Sprintf(`# rules/.../%[1]s.yaml — one provider per file (docs/rule-schema.md)
pack: %[1]s
version: 1
rules:
  - id: %[1]s/model-literal
    kind: hosted-llm
    provider: %[1]s
    languages: [python, javascript, typescript]
    keywords: ["%[1]s-"]                       # Aho-Corasick prefilter — MANDATORY
    pattern: 'model\s*[:=]\s*["''](?P<model>%[1]s-[\w.\-]+)["'']'
    regions: [code, string]
    claim: { name: "${model}" }
    confidence: 0.85
`, name)
}

func rulepackFixture(name string) string {
	return fmt.Sprintf(`# sample fixture for the %[1]s pack.
# Each rule needs >=1 positive and >=1 negative annotation.

# airom: %[1]s/model-literal
model = "%[1]s-large"

# airom-ok: %[1]s/model-literal
model = "some-other-model"
`, name)
}

func detectorTemplate(pkg, name string) string {
	return fmt.Sprintf(`// Package %[1]s detects %[2]s assets.
package %[1]s

import (
	"context"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// New returns the %[2]s detector. The composition root wires it explicitly
// (no init(); go generate ./internal/detectors/all registers it).
func New() *Detector { return &Detector{} }

// Detector detects %[2]s assets.
type Detector struct{}

// ID is stable and namespaced (it becomes the SARIF ruleId).
func (*Detector) ID() string { return %[1]q + "/v1" }

// Version bumps on any behavior change (CI enforces detector-diff => bump).
func (*Detector) Version() int { return 1 }

// Selector declares which files reach DetectFile.
func (*Detector) Selector() detect.Selector {
	return detect.Selector{
		// TODO: narrow this — extensions, basenames, magic, or language.
		Extensions: []string{".TODO"},
		Need:       detect.NeedContent,
	}
}

// DetectFile inspects one file and emits component claims.
func (d *Detector) DetectFile(ctx context.Context, f *detect.File) ([]detect.Finding, error) {
	content, err := f.Content()
	if err != nil {
		return nil, err // becomes an Unknown; never kills the scan
	}
	_ = content
	// TODO: parse and emit findings.
	return []detect.Finding{{
		Claim: detect.ComponentClaim{
			Kind: airom.KindLibrary,
			Name: f.Base(),
		},
		Occurrence: airom.Occurrence{
			Method:     airom.MethodSourceCode,
			Confidence: 0.5,
		},
	}}, nil
}
`, pkg, name)
}

func detectorTestTemplate(pkg, name string) string {
	return fmt.Sprintf(`package %[1]s_test

import (
	"testing"

	"github.com/Roro1727/airom/internal/detectors/%[1]s"
	"github.com/Roro1727/airom/pkg/airom/detectortest"
)

func Test%[2]s(t *testing.T) {
	detectortest.Run(t, %[1]s.New(), detectortest.Fixtures{Dir: "testdata"})
}
`, pkg, capitalize(name))
}

// capitalize upper-cases the first letter for a Go test function name,
// stripping dashes (detector names are [a-z0-9-]+).
func capitalize(s string) string {
	s = strings.ReplaceAll(s, "-", "")
	if s == "" {
		return "Detector"
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
