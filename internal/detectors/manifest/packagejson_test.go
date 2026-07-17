package manifest

import (
	"context"
	"testing"

	"github.com/Roro1727/airom/pkg/airom/detect"
)

// TestNpmDepsLayoutIndependent locks the fix for the single-line/minified miss:
// the pretty, inline-object, and fully minified layouts must all yield the same
// dependencies. (Phase 10 review, detectors finding.)
func TestNpmDepsLayoutIndependent(t *testing.T) {
	cases := map[string]string{
		"minified": `{"name":"x","dependencies":{"openai":"^4.0.0","langchain":"^0.1"}}`,
		"inline":   "{\n  \"dependencies\": { \"openai\": \"^4.0.0\", \"langchain\": \"^0.1\" }\n}\n",
		"pretty":   "{\n  \"dependencies\": {\n    \"openai\": \"^4.0.0\",\n    \"langchain\": \"^0.1\"\n  }\n}\n",
	}
	for name, content := range cases {
		deps := npmDeps([]byte(content), "dependencies")
		if len(deps) != 2 {
			t.Errorf("%s: got %d deps, want 2: %+v", name, len(deps), deps)
			continue
		}
		if deps[0].name != "openai" || deps[0].spec != "^4.0.0" {
			t.Errorf("%s: dep0 = %+v, want openai ^4.0.0", name, deps[0])
		}
		if deps[1].name != "langchain" {
			t.Errorf("%s: dep1 name = %q, want langchain", name, deps[1].name)
		}
		if deps[0].line < 1 {
			t.Errorf("%s: dep0 line = %d, want >= 1", name, deps[0].line)
		}
	}
}

// npmDeps must skip a decoy "dependencies" appearing inside an earlier value
// and still find the real object.
func TestNpmDepsSkipsDecoyKey(t *testing.T) {
	content := `{"scripts":{"x":"echo dependencies"},"dependencies":{"openai":"^4.0.0"}}`
	deps := npmDeps([]byte(content), "dependencies")
	if len(deps) != 1 || deps[0].name != "openai" {
		t.Fatalf("deps = %+v, want [openai]", deps)
	}
}

// TestPackageJSONMinifiedEndToEnd proves the whole detector picks up deps from a
// minified manifest, not just the pretty-printed fixture.
func TestPackageJSONMinifiedEndToEnd(t *testing.T) {
	content := `{"name":"x","dependencies":{"openai":"^4.0.0","langchain":"^0.1"}}`
	f := detect.NewFile(
		detect.FileRef{Path: "package.json", Size: int64(len(content))},
		[]byte(content),
		detect.FileProviders{Content: func() ([]byte, bool, error) { return []byte(content), false, nil }},
	)
	got, err := NewPackageJSON().DetectFile(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (openai, langchain): %+v", len(got), got)
	}
}
