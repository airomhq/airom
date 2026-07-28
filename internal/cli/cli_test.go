package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/app"
)

// captureScan substitutes the app.Run seam and returns a pointer that will
// hold the Config the command resolved.
func captureScan(t *testing.T) **app.Config {
	t.Helper()
	var captured *app.Config
	orig := runScan
	runScan = func(_ context.Context, cfg *app.Config) error {
		captured = cfg
		return nil
	}
	t.Cleanup(func() { runScan = orig })
	return &captured
}

// clearAiromEnv unsets ambient AIROM_* variables so tests are hermetic
// regardless of the developer's shell. t.Setenv registers restoration of the
// original value (and forbids t.Parallel, which the shared runScan seam
// requires anyway).
func clearAiromEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "AIROM_") {
			t.Setenv(name, os.Getenv(name)) // registers restore
			_ = os.Unsetenv(name)
		}
	}
}

// execute runs the root command with args and returns stdout and the error.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	clearAiromEnv(t)
	root := newRootCmd(BuildInfo{Version: "test", Commit: "abc", Date: "today"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestHelpRuns(t *testing.T) {
	out, err := execute(t, "--help")
	if err != nil {
		t.Fatalf("--help error: %v", err)
	}
	for _, cmd := range []string{"scan", "fs", "repo", "image", "k8s", "clean", "version"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("--help missing command %q", cmd)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	out, err := execute(t, "version")
	if err != nil {
		t.Fatalf("version error: %v", err)
	}
	for _, want := range []string{"airom test", "commit: abc", "built:  today", "go:"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q in:\n%s", want, out)
		}
	}
}

func TestFSResolvesConfig(t *testing.T) {
	got := captureScan(t)
	t.Chdir(t.TempDir())

	_, err := execute(
		t, "fs", ".",
		"--parallel", "3",
		"-o", "table", "-o", "cyclonedx=bom.json",
		"--io-budget", "64m",
		"--fail-on", "hosted-llm&confidence>=0.9",
		"--ignore", "**/fixtures/**",
	)
	if err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if cfg == nil {
		t.Fatal("runScan not invoked")
	}
	if cfg.Source != app.SourceFS || cfg.Target != "." {
		t.Errorf("source/target = %v/%q", cfg.Source, cfg.Target)
	}
	if cfg.Parallel != 3 {
		t.Errorf("Parallel = %d, want 3", cfg.Parallel)
	}
	if cfg.IOBudget != 64<<20 {
		t.Errorf("IOBudget = %d, want 64MiB", cfg.IOBudget)
	}
	if len(cfg.Outputs) != 2 || cfg.Outputs[1].Path != "bom.json" {
		t.Errorf("Outputs = %v", cfg.Outputs)
	}
	if cfg.Policy == nil {
		t.Error("Policy = nil, want parsed --fail-on policy")
	}
	if len(cfg.IgnoreGlobs) != 1 || cfg.IgnoreGlobs[0] != "**/fixtures/**" {
		t.Errorf("IgnoreGlobs = %v", cfg.IgnoreGlobs)
	}
}

func TestWideFlagResolves(t *testing.T) {
	// default: off
	got := captureScan(t)
	t.Chdir(t.TempDir())
	if _, err := execute(t, "fs", "."); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	if (*got).Wide {
		t.Error("Wide = true without --wide")
	}

	// --wide flips it, and it reaches the table writer via emit()
	got = captureScan(t)
	if _, err := execute(t, "fs", ".", "--wide"); err != nil {
		t.Fatalf("fs --wide error: %v", err)
	}
	if !(*got).Wide {
		t.Error("Wide = false with --wide")
	}
}

// TestCVEDefaultsOnAndOptOut pins the default-on CVE overlay and every opt-out:
// --no-cve, an explicit --cve=false, --offline, and `cve: false` in a config
// file. Honoring the file value matters — silently ignoring it would leave an
// airgapped user making live OSV queries.
func TestCVEDefaultsOnAndOptOut(t *testing.T) {
	check := func(t *testing.T, want bool, args ...string) {
		t.Helper()
		got := captureScan(t)
		t.Chdir(t.TempDir())
		if _, err := execute(t, append([]string{"fs", "."}, args...)...); err != nil {
			t.Fatalf("fs %v: %v", args, err)
		}
		if (*got) == nil {
			t.Fatal("runScan not invoked")
		}
		if (*got).CVE != want {
			t.Errorf("fs %v: CVE = %v, want %v", args, (*got).CVE, want)
		}
	}
	t.Run("default on", func(t *testing.T) { check(t, true) })
	t.Run("--no-cve off", func(t *testing.T) { check(t, false, "--no-cve") })
	t.Run("--cve=false off", func(t *testing.T) { check(t, false, "--cve=false") })
	t.Run("--offline off", func(t *testing.T) { check(t, false, "--offline") })

	t.Run("cve:false in .airom.yaml off", func(t *testing.T) {
		got := captureScan(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte("cve: false\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		if _, err := execute(t, "fs", "."); err != nil {
			t.Fatalf("fs: %v", err)
		}
		if (*got).CVE {
			t.Error("cve: false in .airom.yaml must disable the overlay, not be silently ignored")
		}
	})
}

// TestEOLDefaultsOnAndOptOut pins the EOL overlay's flag contract. Unlike the
// CVE overlay it reads an embedded catalog, so --offline must NOT disable it:
// an offline scan can still report what stops working and when.
func TestEOLDefaultsOnAndOptOut(t *testing.T) {
	check := func(t *testing.T, wantDisabled bool, args ...string) {
		t.Helper()
		got := captureScan(t)
		t.Chdir(t.TempDir())
		if _, err := execute(t, append([]string{"fs", "."}, args...)...); err != nil {
			t.Fatalf("fs %v: %v", args, err)
		}
		if (*got).NoEOL != wantDisabled {
			t.Errorf("fs %v: NoEOL = %v, want %v", args, (*got).NoEOL, wantDisabled)
		}
	}
	t.Run("default on", func(t *testing.T) { check(t, false) })
	t.Run("--no-eol off", func(t *testing.T) { check(t, true, "--no-eol") })
	t.Run("--offline keeps it on", func(t *testing.T) { check(t, false, "--offline") })

	t.Run("no-eol:true in .airom.yaml", func(t *testing.T) {
		got := captureScan(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte("no-eol: true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		if _, err := execute(t, "fs", "."); err != nil {
			t.Fatalf("fs: %v", err)
		}
		if !(*got).NoEOL {
			t.Error("no-eol: true in .airom.yaml must disable the overlay")
		}
	})
}

func TestConfigPrecedence(t *testing.T) {
	got := captureScan(t)
	dir := t.TempDir()
	yaml := "parallel: 4\nio-budget: 32m\noutput:\n  - yaml\nmin-confidence: 0.5\n"
	if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	// file only: file beats defaults
	if _, err := execute(t, "fs", "."); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if cfg.Parallel != 4 || cfg.IOBudget != 32<<20 || cfg.MinConfidence != 0.5 {
		t.Errorf("file layer not applied: parallel=%d io=%d conf=%v", cfg.Parallel, cfg.IOBudget, cfg.MinConfidence)
	}
	if len(cfg.Outputs) != 1 || cfg.Outputs[0].Format != app.FormatYAML {
		t.Errorf("Outputs = %v, want yaml from file", cfg.Outputs)
	}

	// env beats file (executeNoClear: execute's hermetic scrub would unset
	// the very vars this test sets)
	clearAiromEnv(t)
	t.Setenv("AIROM_PARALLEL", "8")
	t.Setenv("AIROM_OUTPUT", "table,sarif=airom.sarif")
	if err := executeNoClear(t, "fs", "."); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg = *got
	if cfg.Parallel != 8 {
		t.Errorf("Parallel = %d, want env 8 over file 4", cfg.Parallel)
	}
	if len(cfg.Outputs) != 2 || cfg.Outputs[1].Path != "airom.sarif" {
		t.Errorf("Outputs = %v, want env list", cfg.Outputs)
	}

	// flag beats env
	if err := executeNoClear(t, "fs", ".", "--parallel", "2"); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg = *got
	if cfg.Parallel != 2 {
		t.Errorf("Parallel = %d, want flag 2 over env 8", cfg.Parallel)
	}
	// unrelated file keys still apply
	if cfg.IOBudget != 32<<20 {
		t.Errorf("IOBudget = %d, want file 32MiB", cfg.IOBudget)
	}
}

func TestFormatAlias(t *testing.T) {
	got := captureScan(t)
	t.Chdir(t.TempDir())

	if _, err := execute(t, "fs", ".", "--format", "json"); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if len(cfg.Outputs) != 1 || cfg.Outputs[0].Format != app.FormatJSON {
		t.Errorf("Outputs = %v, want single json", cfg.Outputs)
	}

	if _, err := execute(t, "fs", ".", "--format", "json", "-o", "table"); err == nil {
		t.Error("want error for --format with -o, got nil")
	}
}

func TestExitCodeImpliesMatchAny(t *testing.T) {
	got := captureScan(t)
	t.Chdir(t.TempDir())

	if _, err := execute(t, "fs", ".", "--exit-code", "5"); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if cfg.Policy == nil {
		t.Fatal("Policy = nil, want match-any when --exit-code set without --fail-on")
	}
	if cfg.ExitCode != 5 {
		t.Errorf("ExitCode = %d, want 5", cfg.ExitCode)
	}
}

func TestBadFailOnIsUsageError(t *testing.T) {
	t.Chdir(t.TempDir())
	_, err := execute(t, "fs", ".", "--fail-on", "confidence>>1")
	if err == nil {
		t.Fatal("want parse error, got nil")
	}
}

func TestImageArgValidation(t *testing.T) {
	captureScan(t)
	if _, err := execute(t, "image"); err == nil || !strings.Contains(err.Error(), "reference or --input") {
		t.Errorf("image with no args: err = %v", err)
	}
	if _, err := execute(t, "image", "ubuntu:24.04", "--input", "x.tar"); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("image ref+input: err = %v", err)
	}
}

func TestScanAutoDetect(t *testing.T) {
	got := captureScan(t)
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := execute(t, "scan", "."); err != nil {
		t.Fatalf("scan .: %v", err)
	}
	if (*got).Source != app.SourceFS {
		t.Errorf("scan . source = %v, want fs", (*got).Source)
	}

	if _, err := execute(t, "scan", "https://github.com/acme/x.git"); err != nil {
		t.Fatalf("scan git url: %v", err)
	}
	if (*got).Source != app.SourceRepo {
		t.Errorf("scan git url source = %v, want repo", (*got).Source)
	}

	if _, err := execute(t, "scan", "image:ubuntu:24.04"); err != nil {
		t.Fatalf("scan image: %v", err)
	}
	if (*got).Source != app.SourceImage || (*got).Target != "ubuntu:24.04" {
		t.Errorf("scan forced image = %v %q", (*got).Source, (*got).Target)
	}
}

func TestCleanCommand(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "airom-cache")
	if err := os.MkdirAll(filepath.Join(cacheDir, "ns1"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())

	out, err := execute(t, "clean", "--cache-dir", cacheDir)
	if err != nil {
		t.Fatalf("clean error: %v", err)
	}
	if !strings.Contains(out, "removed cache") {
		t.Errorf("clean output = %q", out)
	}
	if _, err := os.Stat(cacheDir); !os.IsNotExist(err) {
		t.Error("cache dir still exists after clean")
	}

	// idempotent: cleaning again reports no cache
	out, err = execute(t, "clean", "--cache-dir", cacheDir)
	if err != nil {
		t.Fatalf("second clean error: %v", err)
	}
	if !strings.Contains(out, "no cache") {
		t.Errorf("second clean output = %q", out)
	}
}

func TestQuietVerboseConflict(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := execute(t, "fs", ".", "-q", "-v"); err == nil {
		t.Error("want -q/-v conflict error, got nil")
	}
}

func TestFailOnDefaultsExitCodeToOne(t *testing.T) {
	got := captureScan(t)
	t.Chdir(t.TempDir())
	if _, err := execute(t, "fs", ".", "--fail-on", "hosted-llm"); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if cfg.Policy == nil || cfg.ExitCode != 1 {
		t.Errorf("policy=%v exitCode=%d, want active policy with documented default 1", cfg.Policy, cfg.ExitCode)
	}
}

func TestExplicitExitCodeZeroIsReportOnly(t *testing.T) {
	got := captureScan(t)
	t.Chdir(t.TempDir())
	if _, err := execute(t, "fs", ".", "--fail-on", "hosted-llm", "--exit-code", "0"); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if cfg.Policy == nil {
		t.Fatal("Policy = nil, want active policy")
	}
	if cfg.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want explicit 0 preserved (report-only)", cfg.ExitCode)
	}
	// and 0 must survive ApplyDefaults too
	cfg.ApplyDefaults()
	if cfg.ExitCode != 0 {
		t.Errorf("ExitCode after defaults = %d, want 0", cfg.ExitCode)
	}
}

func TestBadEnvValuesAreFatal(t *testing.T) {
	t.Chdir(t.TempDir())
	cases := []struct{ env, val, want string }{
		{"AIROM_EXIT_CODE", "oops", "invalid integer"},
		{"AIROM_EXIT_CODE", "3 ", ""}, // trimmed: must PARSE, not fail (want == "" means success)
		{"AIROM_NO_CACHE", "yes", "invalid boolean"},
		{"AIROM_PARALLEL", "2.9", "invalid integer"},
		{"AIROM_MIN_CONFIDENCE", "high", "invalid number"},
	}
	for _, tc := range cases {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			captureScan(t)
			clearAiromEnv(t)
			t.Setenv(tc.env, tc.val)
			err := executeNoClear(t, "fs", ".")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// executeNoClear is execute without the hermetic env scrub, for tests that
// set their own AIROM_* variables.
func executeNoClear(t *testing.T, args ...string) error {
	t.Helper()
	root := newRootCmd(BuildInfo{Version: "test", Commit: "abc", Date: "today"})
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	return root.ExecuteContext(context.Background())
}

func TestUnknownConfigKeysAreFatal(t *testing.T) {
	captureScan(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte("workerz: 8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := execute(t, "fs", "."); err == nil || !strings.Contains(err.Error(), "unknown configuration key") {
		t.Errorf("file typo: err = %v, want unknown-key error", err)
	}

	t.Chdir(t.TempDir())
	clearAiromEnv(t)
	t.Setenv("AIROM_WORKERZ", "8")
	if err := executeNoClear(t, "fs", "."); err == nil || !strings.Contains(err.Error(), "unknown AIROM_") {
		t.Errorf("env typo: err = %v, want unknown-env error", err)
	}
}

func TestScalarYAMLListKeys(t *testing.T) {
	got := captureScan(t)
	dir := t.TempDir()
	yaml := "output: json\nignore: \"**/fixtures/**\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := execute(t, "fs", "."); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if len(cfg.Outputs) != 1 || cfg.Outputs[0].Format != app.FormatJSON {
		t.Errorf("Outputs = %v, want scalar output: json accepted", cfg.Outputs)
	}
	if len(cfg.IgnoreGlobs) != 1 || cfg.IgnoreGlobs[0] != "**/fixtures/**" {
		t.Errorf("IgnoreGlobs = %v, want scalar ignore accepted", cfg.IgnoreGlobs)
	}
}

func TestEnvFormatBeatsFileOutput(t *testing.T) {
	got := captureScan(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte("output:\n  - yaml\n  - table\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	clearAiromEnv(t)
	t.Setenv("AIROM_FORMAT", "json")
	if err := executeNoClear(t, "fs", "."); err != nil {
		t.Fatalf("fs error: %v", err)
	}
	cfg := *got
	if len(cfg.Outputs) != 1 || cfg.Outputs[0].Format != app.FormatJSON {
		t.Errorf("Outputs = %v, want env format (json) to beat file output list", cfg.Outputs)
	}
}

func TestQuietFromFileOverriddenByVerboseFlag(t *testing.T) {
	captureScan(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".airom.yaml"), []byte("quiet: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	// file quiet + explicit -v: -v wins, no conflict error
	if _, err := execute(t, "fs", ".", "-v"); err != nil {
		t.Fatalf("want -v to override file quiet, got error: %v", err)
	}
	// both explicit flags still conflict
	if _, err := execute(t, "fs", ".", "-v", "-q"); err == nil {
		t.Error("want -q/-v conflict error for explicit flags")
	}
}

func TestCleanRefusesNonAiromDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mydata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	_, err := execute(t, "clean", "--cache-dir", dir)
	if err == nil || !strings.Contains(err.Error(), "not an airom cache directory") {
		t.Fatalf("err = %v, want basename refusal", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Error("directory was removed despite refusal")
	}
}

func TestGuardCacheRemoval(t *testing.T) {
	base := t.TempDir()

	// 1. Arbitrary directory name: refused by the allowlist.
	if err := guardCacheRemoval(filepath.Join(base, "documents")); err == nil {
		t.Error("want refusal for non-airom basename")
	}

	// 2. A legitimate cache dir passes.
	ok := filepath.Join(base, "airom")
	if err := os.MkdirAll(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := guardCacheRemoval(ok); err != nil {
		t.Errorf("legitimate cache dir refused: %v", err)
	}

	// 3. $HOME that happens to be named "airom": refused via os.SameFile
	//    even though the basename passes.
	home := filepath.Join(base, "home", "airom")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if err := guardCacheRemoval(home); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("err = %v, want home refusal", err)
	}

	// 4. Symlinked $HOME: the target must still be refused.
	link := filepath.Join(base, "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", link)
	if err := guardCacheRemoval(home); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("err = %v, want symlinked-home refusal", err)
	}
}

func TestCheckPProfForm(t *testing.T) {
	if err := checkPProfForm([]string{"fs", ".", "--pprof"}); err != nil {
		t.Errorf("bare --pprof: %v", err)
	}
	if err := checkPProfForm([]string{"fs", ".", "--pprof=localhost:7070"}); err != nil {
		t.Errorf("attached addr: %v", err)
	}
	if err := checkPProfForm([]string{"fs", ".", "--pprof", "localhost:7070"}); err == nil {
		t.Error("space-separated addr: want error")
	}
	if err := checkPProfForm([]string{"k8s", "--pprof", "prod"}); err != nil {
		t.Errorf("context after bare --pprof: %v (must not false-positive)", err)
	}
	if err := checkPProfForm([]string{"--", "--pprof", "localhost:7070"}); err != nil {
		t.Errorf("after --: %v", err)
	}
}
