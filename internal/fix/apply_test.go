package fix

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// write creates a file under dir and returns the root it lives in.
func write(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func target(pkg, cur, fixed, file string, line int, snippet string) Target {
	return Target{
		Package: pkg, Current: cur, Fixed: fixed, Fixable: true,
		Sites: []Site{{File: file, Line: line, Snippet: snippet}},
	}
}

// applyOne runs Apply on a single-site Target and returns that one Result, for
// the tests written before a Target could carry several.
func applyOne(t *testing.T, root string, tg Target) (Result, error) {
	t.Helper()
	res, err := Apply(root, tg)
	if len(res) == 0 {
		return Result{}, err
	}
	return res[0], err
}

// TestApplyRewritesOnlyTheVersion is the whole contract of the fix in one test:
// the pin moves, and nothing else on the line or in the file does.
func TestApplyRewritesOnlyTheVersion(t *testing.T) {
	cases := []struct {
		name          string
		file, content string
		tg            Target
		wantLine      string
	}{
		{
			name:     "requirements pin with extras and a comment",
			file:     "requirements.txt",
			content:  "langchain[all]==0.0.310  # pinned by ops\nother==1.0.0\n",
			tg:       target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, "langchain[all]==0.0.310"),
			wantLine: "langchain[all]==0.2.4  # pinned by ops",
		},
		{
			name:     "package.json keeps its quoting and comma",
			file:     "package.json",
			content:  "{\n  \"dependencies\": {\n    \"openai\": \"4.0.0\",\n    \"zod\": \"3.0.0\"\n  }\n}\n",
			tg:       target("openai", "4.0.0", "4.104.0", "package.json", 3, `"openai": "4.0.0",`),
			wantLine: `    "openai": "4.104.0",`,
		},
		{
			name:     "go.mod keeps the v prefix the file uses",
			file:     "go.mod",
			content:  "module x\n\ngo 1.25.0\n\nrequire github.com/tmc/langchaingo v0.1.12 // indirect\n",
			tg:       target("github.com/tmc/langchaingo", "0.1.12", "0.1.13", "go.mod", 5, "require github.com/tmc/langchaingo v0.1.12"),
			wantLine: "require github.com/tmc/langchaingo v0.1.13 // indirect",
		},
		{
			name:     "indentation and CRLF survive",
			file:     "pyproject.toml",
			content:  "[project]\r\ndependencies = [\r\n    \"transformers==4.30.0\",\r\n]\r\n",
			tg:       target("transformers", "4.30.0", "4.53.0", "pyproject.toml", 3, `"transformers==4.30.0",`),
			wantLine: "    \"transformers==4.53.0\",",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			p := write(t, root, c.file, c.content)

			res, err := applyOne(t, root, c.tg)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			got, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.ReplaceAll(string(got), "\r\n", "\n"), "\n")
			if lines[c.tg.Sites[0].Line-1] != c.wantLine {
				t.Errorf("line %d =\n  %q\nwant\n  %q", c.tg.Sites[0].Line, lines[c.tg.Sites[0].Line-1], c.wantLine)
			}
			// Every other line is byte-identical.
			before := strings.Split(strings.ReplaceAll(c.content, "\r\n", "\n"), "\n")
			for i := range before {
				if i == c.tg.Sites[0].Line-1 {
					continue
				}
				if before[i] != lines[i] {
					t.Errorf("line %d changed: %q -> %q", i+1, before[i], lines[i])
				}
			}
			// CRLF input stays CRLF.
			if strings.Contains(c.content, "\r\n") && !strings.Contains(string(got), "\r\n") {
				t.Error("CRLF line endings were converted to LF")
			}
			if res.Line != c.tg.Sites[0].Line || res.File != c.file {
				t.Errorf("Result = %s:%d, want %s:%d", res.File, res.Line, c.file, c.tg.Sites[0].Line)
			}
		})
	}
}

// TestApplyRefusesWhenTheFileMoved: the scan and the fix are separated in time
// by however long the user looked at the table. If the line no longer says what
// the scan saw, rewriting it would corrupt an edit somebody else made.
func TestApplyRefusesWhenTheFileMoved(t *testing.T) {
	cases := []struct {
		name, content string
		tg            Target
		wantSubstr    string
	}{
		{
			name:       "version already changed",
			content:    "langchain==0.5.0\n",
			tg:         target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, "langchain==0.0.310"),
			wantSubstr: "no longer pins",
		},
		{
			name:       "a different package now occupies the line",
			content:    "openai==0.0.310\n",
			tg:         target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, "langchain==0.0.310"),
			wantSubstr: "no longer declares",
		},
		{
			name:       "the file got shorter",
			content:    "langchain==0.0.310\n",
			tg:         target("langchain", "0.0.310", "0.2.4", "requirements.txt", 9, "langchain==0.0.310"),
			wantSubstr: "past the end",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			p := write(t, root, "requirements.txt", c.content)
			if _, err := applyOne(t, root, c.tg); err == nil {
				t.Fatal("Apply succeeded on a file that moved on")
			} else if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("error = %v, want it to mention %q", err, c.wantSubstr)
			}
			got, _ := os.ReadFile(p)
			if string(got) != c.content {
				t.Errorf("a refused fix still wrote to the file: %q", got)
			}
		})
	}
}

// TestApplyRefusesUnfixableTarget: Apply re-checks rather than trusting its
// caller, because --fix-all iterates a plan and the table clicks into it.
func TestApplyRefusesUnfixableTarget(t *testing.T) {
	tg := Target{Package: "pkg", Current: "1.0.0", Fixed: "1.1.0", Reason: "only seen in a lockfile"}
	_, err := Apply(t.TempDir(), tg)
	if !errors.Is(err, ErrNotFixable) {
		t.Fatalf("Apply error = %v, want ErrNotFixable", err)
	}
	if !strings.Contains(err.Error(), "lockfile") {
		t.Errorf("error = %v, want it to carry the reason", err)
	}
}

// TestApplyRefusesToEscapeTheScanRoot. The occurrence path comes from AIROM's
// own scan, not from a user — but this is the one code path that writes, so it
// verifies instead of assuming.
func TestApplyRefusesToEscapeTheScanRoot(t *testing.T) {
	root := t.TempDir()
	outside := write(t, t.TempDir(), "requirements.txt", "langchain==0.0.310\n")
	tg := target("langchain", "0.0.310", "0.2.4", "../../"+filepath.Base(filepath.Dir(outside))+"/requirements.txt", 1, "")
	if _, err := applyOne(t, root, tg); err == nil {
		t.Fatal("Apply followed a path out of the scan root")
	}
}

// TestReplaceVersionMatchesWholeTokensOnly. "4.3" appearing inside "4.30.0"
// must not be rewritten — that turns a pin into nonsense silently, which is the
// worst failure mode this package has.
func TestReplaceVersionMatchesWholeTokensOnly(t *testing.T) {
	cases := []struct {
		line, old, next, want string
		ok                    bool
	}{
		{"transformers==4.30.0", "4.30.0", "4.53.0", "transformers==4.53.0", true},
		{"transformers==4.30.0", "4.3", "9.9", "transformers==4.30.0", false},
		{"transformers==4.30.0", "30.0", "31.0", "transformers==4.30.0", false},
		{`"openai": "1.0.0"`, "1.0.0", "1.2.0", `"openai": "1.2.0"`, true},
		{"pkg>=1.0.0,<2.0.0", "1.0.0", "1.5.0", "pkg>=1.5.0,<2.0.0", true},
		// The first WHOLE-token match wins, and a hash that merely contains the
		// digits is not one.
		{"pkg==1.0.0 --hash=sha256:1.0.0aa", "1.0.0", "1.1.0", "pkg==1.1.0 --hash=sha256:1.0.0aa", true},
	}
	for _, c := range cases {
		got, ok := replaceVersion(c.line, c.old, c.next)
		if got != c.want || ok != c.ok {
			t.Errorf("replaceVersion(%q, %q, %q) = %q,%v want %q,%v",
				c.line, c.old, c.next, got, ok, c.want, c.ok)
		}
	}
}

// TestApplyPreservesMode keeps a read-only-for-group manifest read-only for
// group: the fix is an edit, not a permissions change.
func TestApplyPreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	root := t.TempDir()
	p := write(t, root, "requirements.txt", "langchain==0.0.310\n")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := applyOne(t, root, target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, "")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", st.Mode().Perm())
	}
}

// TestApplyReportsStaleLockfiles. The bump makes the lockfile wrong; AIROM says
// so rather than patching a resolution it cannot compute.
func TestApplyReportsStaleLockfiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json", "{\n  \"dependencies\": {\n    \"openai\": \"4.0.0\"\n  }\n}\n")
	write(t, root, "package-lock.json", `{"lockfileVersion":3}`)

	res, err := applyOne(t, root, target("openai", "4.0.0", "4.104.0", "package.json", 3, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stale) != 1 || res.Stale[0] != "package-lock.json" {
		t.Errorf("Stale = %v, want [package-lock.json]", res.Stale)
	}
	// It must be reported, never rewritten.
	got, _ := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if string(got) != `{"lockfileVersion":3}` {
		t.Errorf("the lockfile was modified: %q", got)
	}
}

// TestApplyIsNotIdempotent asserts the SECOND application refuses rather than
// bumping again — a double click must not walk the version forward twice.
func TestApplyIsNotIdempotent(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "langchain==0.0.310\n")
	tg := target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, "")
	if _, err := applyOne(t, root, tg); err != nil {
		t.Fatal(err)
	}
	if _, err := applyOne(t, root, tg); err == nil {
		t.Error("the second Apply succeeded; a repeated fix must refuse")
	}
	got, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if string(got) != "langchain==0.2.4\n" {
		t.Errorf("file = %q, want a single applied bump", got)
	}
}

// TestRevertRestoresTheLineExactly. A revert after a failed verification has to
// leave the manifest byte-identical to what the user had, or "undo" is a second
// unreviewed edit.
func TestRevertRestoresTheLineExactly(t *testing.T) {
	const original = "langchain[all]==0.0.310  # pinned by ops\r\nother==1.0.0\r\n"
	root := t.TempDir()
	p := write(t, root, "requirements.txt", original)

	res, err := applyOne(t, root, target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) == original {
		t.Fatal("Apply did not change the file")
	}
	if err := Revert(root, res); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != original {
		t.Errorf("after revert the file is\n  %q\nwant\n  %q", got, original)
	}
}

// TestRevertRefusesWhenTheLineMovedOn: if something else edited the pin after
// the fix, restoring the old version would silently discard that change.
func TestRevertRefusesWhenTheLineMovedOn(t *testing.T) {
	root := t.TempDir()
	p := write(t, root, "requirements.txt", "langchain==0.0.310\n")
	res, err := applyOne(t, root, target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("langchain==0.3.0  # hand-picked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Revert(root, res); err == nil {
		t.Fatal("Revert overwrote an edit made after the fix")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "langchain==0.3.0  # hand-picked\n" {
		t.Errorf("the refused revert still wrote: %q", got)
	}
}

// TestResultCarriesBothVersions — Revert re-plans nothing, so the Result is the
// only record of where the pin came from.
func TestResultCarriesBothVersions(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "langchain==0.0.310\n")
	res, err := applyOne(t, root, target("langchain", "0.0.310", "0.2.4", "requirements.txt", 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	if res.Package != "langchain" || res.From != "0.0.310" || res.To != "0.2.4" {
		t.Errorf("Result = %+v, want the package and both versions recorded", res)
	}
}

// TestApplyRefusesAPrefixNamedSibling is the guard against the worst failure
// this package can produce: editing a different package than the one it reports.
//
// `langchain` is a prefix of `langchain-core`, `langchain-community`, and
// `langchain-openai`; `llama-index` of `llama-index-core`. If the pin's line
// number has drifted since the scan — a comment added, a dependency inserted
// above — a substring name check lands on the sibling, finds a whole-token
// version there, and rewrites it. The user is told langchain was fixed while
// langchain is still vulnerable and something else was silently bumped.
func TestApplyRefusesAPrefixNamedSibling(t *testing.T) {
	siblings := []struct {
		pkg, line string
	}{
		{"langchain", "langchain-core==0.0.310"},
		{"langchain", "langchain-community==0.0.310"},
		{"llama-index", "llama-index-core==0.0.310"},
		{"openai", "openai-agents==0.0.310"},
		{"core", "langchain-core==0.0.310"}, // suffix, not just prefix
	}
	for _, s := range siblings {
		t.Run(s.pkg+" vs "+s.line, func(t *testing.T) {
			root := t.TempDir()
			p := write(t, root, "requirements.txt", s.line+"\n")
			_, err := applyOne(t, root, target(s.pkg, "0.0.310", "0.2.4", "requirements.txt", 1, ""))
			if err == nil {
				got, _ := os.ReadFile(p)
				t.Fatalf("Apply rewrote %q while claiming to fix %q; file is now %q", s.line, s.pkg, got)
			}
			if !strings.Contains(err.Error(), "no longer declares") {
				t.Errorf("error = %v, want the package-name refusal", err)
			}
			if got, _ := os.ReadFile(p); string(got) != s.line+"\n" {
				t.Errorf("the refused fix still wrote: %q", got)
			}
		})
	}
}

// TestApplyStillMatchesTheRealPackage — the guard must not be so strict that it
// rejects the spellings each ecosystem actually uses.
func TestApplyStillMatchesTheRealPackage(t *testing.T) {
	cases := []struct{ pkg, line, want string }{
		{"langchain", "langchain==0.0.310", "langchain==0.2.4"},
		{"langchain", "langchain[all]==0.0.310  # ops", "langchain[all]==0.2.4  # ops"},
		{"langchain-core", "langchain_core==0.0.310", "langchain_core==0.2.4"}, // PEP 503
		{"langchain-core", "LangChain-Core==0.0.310", "LangChain-Core==0.2.4"}, // case
		{"@langchain/core", `    "@langchain/core": "0.0.310",`, `    "@langchain/core": "0.2.4",`},
		{"golang.org/x/mod", "\tgolang.org/x/mod v0.0.310", "\tgolang.org/x/mod v0.2.4"},
		// The sibling is present but so is the real package: pick the real one.
		{"langchain", "langchain==0.0.310  # not langchain-core", "langchain==0.2.4  # not langchain-core"},
	}
	for _, c := range cases {
		t.Run(c.pkg+" in "+c.line, func(t *testing.T) {
			root := t.TempDir()
			p := write(t, root, "requirements.txt", c.line+"\n")
			if _, err := applyOne(t, root, target(c.pkg, "0.0.310", "0.2.4", "requirements.txt", 1, "")); err != nil {
				t.Fatalf("Apply refused a legitimate pin: %v", err)
			}
			if got, _ := os.ReadFile(p); string(got) != c.want+"\n" {
				t.Errorf("line =\n  %q\nwant\n  %q", got, c.want+"\n")
			}
		})
	}
}

// TestGoModuleIsNotMatchedInsideALongerPath: golang.org/x/mod must not match
// the line declaring golang.org/x/mod/semver.
func TestGoModuleIsNotMatchedInsideALongerPath(t *testing.T) {
	root := t.TempDir()
	p := write(t, root, "go.mod", "require golang.org/x/mod/semver v0.1.0\n")
	if _, err := applyOne(t, root, target("golang.org/x/mod", "0.1.0", "0.2.0", "go.mod", 1, "")); err == nil {
		got, _ := os.ReadFile(p)
		t.Fatalf("Apply matched a module inside a longer path; file is now %q", got)
	}
}

// TestApplyRewritesEveryPinSite is the fix for the defect that made the feature
// look broken in practice: a package pinned in several manifests was only
// rewritten in one, the report said "updated 1 pin", and the re-scan it told the
// user to run still showed the advisory — because the package genuinely was
// still pinned vulnerable in the manifests nobody touched.
//
// Monorepos make this the normal case, not an exotic one: an api/ and a worker/
// requirements.txt, a manifest per service, a root manifest beside a per-package
// one. Assembly merges those sightings into ONE component, so the plan has to
// carry all of them and Apply has to move all of them.
func TestApplyRewritesEveryPinSite(t *testing.T) {
	root := t.TempDir()
	files := []string{"requirements.txt", "api/requirements.txt", "worker/requirements.txt"}
	for _, f := range files {
		write(t, root, f, "langchain==0.2.16\nother==1.0.0\n")
	}

	tg := Target{
		Package: "langchain", Current: "0.2.16", Fixed: "1.3.9", Fixable: true,
		Sites: []Site{
			{File: "requirements.txt", Line: 1},
			{File: "api/requirements.txt", Line: 1},
			{File: "worker/requirements.txt", Line: 1},
		},
	}
	got, err := Apply(root, tg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Apply returned %d results, want one per pin site (3)", len(got))
	}
	for _, f := range files {
		b, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if rerr != nil {
			t.Fatal(rerr)
		}
		if want := "langchain==1.3.9\nother==1.0.0\n"; string(b) != want {
			t.Errorf("%s =\n  %q\nwant\n  %q", f, b, want)
		}
	}
}

// TestApplyReportsPartialRatherThanClaimingSuccess. If one site's line moved
// since the scan, the sites that were still provable stay applied — rolling them
// back would discard correct remediation over an unrelated edit — but the
// package is NOT fixed, and both halves have to reach the caller.
func TestApplyReportsPartialRatherThanClaimingSuccess(t *testing.T) {
	root := t.TempDir()
	write(t, root, "api/requirements.txt", "langchain==0.2.16\n")
	write(t, root, "worker/requirements.txt", "langchain==9.9.9  # someone bumped this by hand\n")

	tg := Target{
		Package: "langchain", Current: "0.2.16", Fixed: "1.3.9", Fixable: true,
		Sites: []Site{
			{File: "api/requirements.txt", Line: 1},
			{File: "worker/requirements.txt", Line: 1},
		},
	}
	got, err := Apply(root, tg)
	if err == nil {
		t.Fatal("Apply reported success while one manifest still pins the vulnerable version")
	}
	if len(got) != 1 || got[0].File != "api/requirements.txt" {
		t.Fatalf("results = %+v, want the one provable site applied", got)
	}
	// The provable edit stands; the unprovable one is untouched.
	if b, _ := os.ReadFile(filepath.Join(root, "api", "requirements.txt")); string(b) != "langchain==1.3.9\n" {
		t.Errorf("api manifest = %q, want the applied fix", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "worker", "requirements.txt")); string(b) != "langchain==9.9.9  # someone bumped this by hand\n" {
		t.Errorf("worker manifest was rewritten: %q", b)
	}
}
