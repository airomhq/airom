package pgext

import (
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/pkg/airom/detect"
)

func file(path string, body []byte) *detect.File {
	return detect.NewFile(
		detect.FileRef{Path: path, Size: int64(len(body))},
		body,
		detect.FileProviders{Content: func() ([]byte, bool, error) { return body, false, nil }},
	)
}

// realControl is the file a pgvector 0.8.1 install writes.
var realControl = []byte(`# vector extension
comment = 'vector data type and ivfflat and hnsw access methods'
default_version = '0.8.1'
module_pathname = '$libdir/vector'
relocatable = true
trusted = true
`)

func TestControlReadsTheInstalledVersion(t *testing.T) {
	got, err := NewControl().DetectFile(context.Background(),
		file("usr/pgsql-17/share/extension/vector.control", realControl))
	if err != nil {
		t.Fatalf("DetectFile: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Claim.Name != "pgvector" || f.Claim.Version != "0.8.1" {
		t.Errorf("claim = %s %s, want pgvector 0.8.1", f.Claim.Name, f.Claim.Version)
	}
	if f.Claim.Kind != airom.KindVectorDB || f.Claim.Provider != "pgvector" {
		t.Errorf("kind/provider = %s/%s", f.Claim.Kind, f.Claim.Provider)
	}
	if f.Occurrence.Confidence != confControl {
		t.Errorf("confidence = %v, want %v", f.Occurrence.Confidence, confControl)
	}
	if f.Occurrence.Location.Line != 3 {
		t.Errorf("line = %d, want 3 (where default_version is)", f.Occurrence.Location.Line)
	}
	// The distinction between "installed on disk" and "loaded in a database"
	// has to survive into the evidence, or the claim overstates itself.
	if !contains(f.Occurrence.Snippet, "ALTER EXTENSION") {
		t.Errorf("evidence %q does not say the running database may differ", f.Occurrence.Snippet)
	}
}

func TestControlVariants(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"unquoted", "default_version = 0.7.4\n", "0.7.4"},
		{"no spaces", "default_version='0.8.0'\n", "0.8.0"},
		{"leading whitespace", "   default_version = '1.0.0'\n", "1.0.0"},
		{"trailing comment", "default_version = '0.8.1' # bumped\n", "0.8.1"},
		// A control file with no default_version is still proof the extension
		// is installed; the component is reported with the version unknown.
		{"absent", "comment = 'no version here'\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NewControl().DetectFile(context.Background(),
				file("share/extension/vector.control", []byte(c.body)))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1 — an extension with no version is still installed", len(got))
			}
			if got[0].Claim.Version != c.want {
				t.Errorf("version = %q, want %q", got[0].Claim.Version, c.want)
			}
		})
	}
}

// TestControlIgnoresOrdinaryExtensions is the AIBOM-not-SBOM guard: a
// PostgreSQL install carries dozens of control files and only the AI ones
// belong in the output.
func TestControlIgnoresOrdinaryExtensions(t *testing.T) {
	for _, name := range []string{"plpgsql", "hstore", "postgis", "pg_trgm", "uuid-ossp"} {
		got, err := NewControl().DetectFile(context.Background(),
			file("share/extension/"+name+".control", []byte("default_version = '1.0'\n")))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 0 {
			t.Errorf("%s produced %d finding(s); only AI extensions belong in an AIBOM", name, len(got))
		}
	}
}

func TestModulePathAnchoring(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// The layouts the major distributions actually use.
		{"usr/pgsql-17/lib/vector.so", true},
		{"usr/lib/postgresql/17/lib/vector.so", true},
		{"opt/postgresql/16/lib/vector.so", true},
		// Not an AI extension.
		{"usr/pgsql-17/lib/pgcrypto.so", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			got, err := NewModule().DetectFile(context.Background(), file(c.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) > 0) != c.want {
				t.Errorf("got %d findings, want any=%v", len(got), c.want)
			}
			if c.want && got[0].Claim.Version != "" {
				t.Errorf("module claimed version %q; only the control file can supply one", got[0].Claim.Version)
			}
		})
	}
}

// TestModuleSelectorRejectsABareVectorSo pins the reason the module rule is
// path-anchored: "vector.so" anywhere else is far too generic to claim a
// database extension from.
func TestModuleSelectorRejectsABareVectorSo(t *testing.T) {
	idx, err := detect.NewIndex([]detect.Detector{NewModule()})
	if err != nil {
		t.Fatalf("selector does not compile: %v", err)
	}
	for _, p := range []string{"home/me/build/vector.so", "usr/lib/vector.so", "opt/app/vector.so"} {
		if got := idx.Match(detect.FileRef{Path: p, Size: 10}, nil); len(got) != 0 {
			t.Errorf("%s matched; a vector.so outside a PostgreSQL lib dir must not claim pgvector", p)
		}
	}
	if got := idx.Match(detect.FileRef{Path: "usr/pgsql-17/lib/vector.so", Size: 10}, nil); len(got) == 0 {
		t.Error("a vector.so inside a PostgreSQL lib dir did not match — the test above proves nothing")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
