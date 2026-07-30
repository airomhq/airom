package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// clearCI blanks every CI marker for the duration of a test, so the result does
// not depend on whether the suite itself is running in a pipeline. t.Setenv
// restores the previous values afterwards.
func clearCI(t *testing.T) {
	t.Helper()
	for _, k := range ciEnvVars {
		t.Setenv(k, "")
	}
}

// countingRules stands in for the release channel and records every request, so
// a test can assert the network was never touched rather than only that the
// return value looked right.
func countingRules(t *testing.T) (base string, hits *atomic.Int64) {
	t.Helper()
	hits = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// TestAutoUpdateRulesStandsDown pins every condition under which a scan must
// not reach the network. Each is a separate promise: CI reproducibility,
// --offline as an assertion rather than a preference, and --no-cached-rules
// meaning the embedded packs full stop.
func TestAutoUpdateRulesStandsDown(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		env    map[string]string
	}{
		{"disabled", func(c *Config) { c.AutoUpdateRules = false }, nil},
		{"offline", func(c *Config) { c.Offline = true }, nil},
		{"no-cached-rules", func(c *Config) { c.NoCachedRules = true }, nil},
		{"ci", func(*Config) {}, map[string]string{"CI": "true"}},
		{"github actions", func(*Config) {}, map[string]string{"GITHUB_ACTIONS": "true"}},
		{"gitlab", func(*Config) {}, map[string]string{"GITLAB_CI": "true"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearCI(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			base, hits := countingRules(t)
			cfg := &Config{AutoUpdateRules: true, CacheDir: t.TempDir(), RulesSource: base}
			c.mutate(cfg)

			if note := autoUpdateRules(context.Background(), cfg); note != "" {
				t.Errorf("note = %q, want none", note)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("made %d request(s); a scan must not reach the network here", got)
			}
		})
	}
}

// TestAutoUpdateRulesEnabledDoesReachOut is the control for the table above:
// with every stand-down condition cleared, the check actually happens. Without
// it, a bug that disabled auto-update outright would leave those subtests
// passing for the wrong reason.
func TestAutoUpdateRulesEnabledDoesReachOut(t *testing.T) {
	clearCI(t)
	base, hits := countingRules(t)
	cfg := &Config{AutoUpdateRules: true, CacheDir: t.TempDir(), RulesSource: base}

	// The server 404s, so nothing installs and no note is produced — the point
	// is only that the attempt was made.
	if note := autoUpdateRules(context.Background(), cfg); note != "" {
		t.Errorf("note = %q, want none from a failing server", note)
	}
	if hits.Load() == 0 {
		t.Fatal("no request made — auto-update never reached the network with everything enabled")
	}
}

func TestInCI(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"true", "true", true},
		{"1", "1", true},
		{"anything", "yes", true},
		// A pipeline that explicitly says it is not one must be believed;
		// several tools export CI=false rather than unsetting it.
		{"false", "false", false},
		{"False", "False", false},
		{"zero", "0", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearCI(t)
			t.Setenv("CI", c.value)
			if got := inCI(); got != c.want {
				t.Errorf("inCI() with CI=%q = %v, want %v", c.value, got, c.want)
			}
		})
	}
}
