package app

import (
	"os"
	"testing"
)

// TestMain isolates the whole package from the developer's real airom cache.
//
// A scan resolves its rule base from the cache directory, and a fetched bundle
// OVERRIDES the embedded packs. Any test that builds a Config without setting
// CacheDir therefore inherits whatever bundle happens to be installed on the
// machine — so a suite that is green on a clean checkout goes red the moment
// someone runs `airom rules update`, with a failure that points at the rule
// engine rather than at the cache.
//
// That was survivable while fetching required an explicit command. Auto-update
// makes a populated cache the default state, so the coupling gets closed here
// rather than left as a trap. Tests that care about cache behavior still set
// CacheDir themselves and are unaffected.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "airom-app-cache")
	if err != nil {
		os.Exit(1)
	}
	// Redirect at the source: ApplyDefaults copies DefaultCacheDir() into
	// Config.CacheDir before rules are resolved, so overriding only the
	// later lookup would be bypassed entirely.
	defaultCacheDir = func() string { return tmp }
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}
