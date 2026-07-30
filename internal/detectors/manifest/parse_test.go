package manifest

import "testing"

func TestVersionSpec(t *testing.T) {
	const (
		bareExact = true
		bareRange = false
	)
	cases := []struct {
		name       string
		spec       string
		bare       bool
		version    string
		constraint string
	}{
		// Exact pins — a single release, named as such.
		{"pep440 pin", "==1.30.0", bareExact, "1.30.0", ""},
		{"pep440 arbitrary equality", "===1.30.0", bareExact, "1.30.0", ""},
		{"npm explicit equals", "=4.28.4", bareExact, "4.28.4", ""},
		{"npm bare is exact", "4.28.4", bareExact, "4.28.4", ""},
		{"go module version", "v1.2.3", bareExact, "v1.2.3", ""},
		{"prerelease pin", "==1.0.0-beta.9", bareExact, "1.0.0-beta.9", ""},
		{"maven coordinate", "0.35.0", bareExact, "0.35.0", ""},
		{"pin with surrounding space", "  ==  1.30.0  ", bareExact, "1.30.0", ""},

		// Ranges — the lower bound must never become the version.
		{"greater or equal", ">=0.25.0", bareExact, "", ">=0.25.0"},
		{"compatible release", "~=0.2.0", bareExact, "", "~=0.2.0"},
		{"caret", "^4.20.0", bareExact, "", "^4.20.0"},
		{"tilde", "~0.2.5", bareExact, "", "~0.2.5"},
		{"bounded", ">=4.40,<5.0", bareExact, "", ">=4.40,<5.0"},
		{"npm space-separated bound", ">=4.0.0 <5.0.0", bareExact, "", ">=4.0.0 <5.0.0"},
		{"npm alternatives", "^4.0.0 || ^5.0.0", bareExact, "", "^4.0.0 || ^5.0.0"},
		{"wildcard segment", "1.2.x", bareExact, "", "1.2.x"},
		{"pinned wildcard is still a range", "==1.2.*", bareExact, "", "==1.2.*"},
		{"exclusion", "!=1.4.0", bareExact, "", "!=1.4.0"},

		// A bare spec means different things in different ecosystems, and this
		// is the only thing the bare flag changes.
		{"cargo bare is a caret range", "1.0", bareRange, "", "1.0"},
		{"poetry bare is a caret range", "1.40.0", bareRange, "", "1.40.0"},

		// Neither a version nor a usable constraint.
		{"empty", "", bareExact, "", ""},
		{"any", "*", bareExact, "", ""},
		{"dist-tag", "latest", bareExact, "", "latest"},
		{"git url", "github:openai/openai-node", bareExact, "", "github:openai/openai-node"},
		{"workspace protocol", "workspace:*", bareExact, "", "workspace:*"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			version, constraint := versionSpec(c.spec, c.bare)
			if version != c.version || constraint != c.constraint {
				t.Errorf("versionSpec(%q, bare=%v) = (%q, %q), want (%q, %q)",
					c.spec, c.bare, version, constraint, c.version, c.constraint)
			}
			if version != "" && constraint != "" {
				t.Errorf("versionSpec(%q) set both version and constraint — they are mutually exclusive", c.spec)
			}
		})
	}
}

func TestParsePEP508KeepsOperators(t *testing.T) {
	// The raw specifier must survive the split. Stripping the operator here
	// would erase the only thing separating a pin from a range.
	cases := []struct{ in, name, spec string }{
		{"openai==1.30.0", "openai", "==1.30.0"},
		{"anthropic>=0.25.0", "anthropic", ">=0.25.0"},
		{"transformers>=4.40,<5.0", "transformers", ">=4.40,<5.0"},
		{"uvicorn[standard]>=0.29.0", "uvicorn", ">=0.29.0"},
		{`pinecone-client==4.1.0 ; python_version >= "3.9"`, "pinecone-client", "==4.1.0"},
		{"tiktoken", "tiktoken", ""},
		{"example @ https://example.invalid/pkg.whl", "example", ""},
	}
	for _, c := range cases {
		name, spec := parsePEP508(c.in)
		if name != c.name || spec != c.spec {
			t.Errorf("parsePEP508(%q) = (%q, %q), want (%q, %q)", c.in, name, spec, c.name, c.spec)
		}
	}
}
