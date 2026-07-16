package detect

import (
	"context"
	"testing"
)

type fakeDet struct {
	id  string
	sel Selector
}

func (f *fakeDet) ID() string         { return f.id }
func (f *fakeDet) Version() int       { return 1 }
func (f *fakeDet) Selector() Selector { return f.sel }
func (f *fakeDet) DetectFile(context.Context, *File) ([]Finding, error) {
	return nil, nil
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"**/*.py", "a.py", true},
		{"**/*.py", "deep/nested/a.py", true},
		{"**/*.py", "a.txt", false},
		{"prompts/**", "prompts/x/y.txt", true},
		{"prompts/**", "prompts", true}, // trailing ** matches zero segments
		{"prompts/**", "other/prompts/x", false},
		{"**/prompts/**", "a/prompts/x", true},
		{"*.json", "config.json", true},
		{"*.json", "sub/config.json", false},
		{"sub/*.json", "sub/config.json", true},
		{"**", "anything/at/all", true},
		{"[ab].py", "a.py", true},
		{"[ab].py", "c.py", false},
	}
	for _, tc := range cases {
		if got := Match(tc.pattern, tc.path); got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
	if ValidateGlob("[bad") {
		t.Error("ValidateGlob accepted an invalid class")
	}
	if !ValidateGlob("**/*.py") {
		t.Error("ValidateGlob rejected a valid pattern")
	}
}

func TestIndexRouting(t *testing.T) {
	byExt := &fakeDet{id: "ext", sel: Selector{Extensions: []string{".GGUF"}}}
	byBase := &fakeDet{id: "base", sel: Selector{Basenames: []string{"requirements.txt"}}}
	byGlob := &fakeDet{id: "glob", sel: Selector{PathGlobs: []string{"**/prompts/**"}}}
	byLang := &fakeDet{id: "lang", sel: Selector{Languages: []Language{LangPython}}}
	byMagic := &fakeDet{id: "magic", sel: Selector{Extensions: []string{".bin"}, Magic: []Magic{{Offset: 0, Bytes: []byte("GGUF")}}}}
	bySize := &fakeDet{id: "size", sel: Selector{Extensions: []string{".py"}, MaxSize: 10}}

	ix, err := NewIndex([]Detector{byExt, byBase, byGlob, byLang, byMagic, bySize})
	if err != nil {
		t.Fatal(err)
	}

	ids := func(ref FileRef, header []byte) []string {
		var out []string
		for _, d := range ix.Match(ref, header) {
			out = append(out, d.ID())
		}
		return out
	}

	got := ids(FileRef{Path: "models/x.gguf", Size: 1 << 30}, []byte("GGUFxxxx"))
	if len(got) != 1 || got[0] != "ext" {
		t.Errorf("gguf: %v, want [ext] (extensions are case-insensitive)", got)
	}

	got = ids(FileRef{Path: "app.py", Size: 100, Language: LangPython}, []byte("import openai"))
	if len(got) != 1 || got[0] != "lang" {
		t.Errorf("py 100B: %v, want [lang] (size detector gated by MaxSize)", got)
	}
	got = ids(FileRef{Path: "app.py", Size: 5, Language: LangPython}, nil)
	if len(got) != 2 { // lang + size
		t.Errorf("py 5B: %v, want lang+size", got)
	}

	got = ids(FileRef{Path: "requirements.txt", Size: 10}, nil)
	if len(got) != 1 || got[0] != "base" {
		t.Errorf("requirements: %v", got)
	}

	got = ids(FileRef{Path: "src/prompts/system.txt", Size: 10}, nil)
	if len(got) != 1 || got[0] != "glob" {
		t.Errorf("prompts glob: %v", got)
	}

	// magic requires BOTH ext and signature (AND across dimensions)
	got = ids(FileRef{Path: "weights.bin", Size: 10}, []byte("GGUFdata"))
	if len(got) != 1 || got[0] != "magic" {
		t.Errorf("magic hit: %v", got)
	}
	got = ids(FileRef{Path: "weights.bin", Size: 10}, []byte("nope"))
	if len(got) != 0 {
		t.Errorf("magic miss: %v, want none", got)
	}
}

func TestIndexRejectsDuplicatesAndBadGlobs(t *testing.T) {
	if _, err := NewIndex([]Detector{
		&fakeDet{id: "same"}, &fakeDet{id: "same"},
	}); err == nil {
		t.Error("duplicate IDs accepted")
	}
	if _, err := NewIndex([]Detector{
		&fakeDet{id: "bad", sel: Selector{PathGlobs: []string{"[oops"}}},
	}); err == nil {
		t.Error("invalid glob accepted")
	}
}

func TestZeroSelectorMatchesEverything(t *testing.T) {
	all := &fakeDet{id: "all"}
	ix, err := NewIndex([]Detector{all})
	if err != nil {
		t.Fatal(err)
	}
	if got := ix.Match(FileRef{Path: "anything.xyz", Size: 1 << 40}, nil); len(got) != 1 {
		t.Errorf("zero selector should match everything, got %v", got)
	}
}

func TestFileContentCachingAndSeekability(t *testing.T) {
	reads := 0
	f := NewFile(FileRef{Path: "x.py", Size: 4}, []byte("data"), FileProviders{
		Content: func() ([]byte, bool, error) { reads++; return []byte("data"), false, nil },
	})
	if _, err := f.Content(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Content(); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Errorf("provider invoked %d times, want 1 (read-once)", reads)
	}
	if _, err := f.ReaderAt(); err != ErrNotSeekable {
		t.Errorf("nil ReaderAt provider: err = %v, want ErrNotSeekable", err)
	}
	if f.Base() != "x.py" {
		t.Errorf("Base = %q", f.Base())
	}
}

func TestLanguageOf(t *testing.T) {
	if LanguageOf("a/b/chat.py") != LangPython || LanguageOf("X.TSX") != LangTypeScript || LanguageOf("m.gguf") != LangUnknown {
		t.Error("LanguageOf misclassifies")
	}
}
