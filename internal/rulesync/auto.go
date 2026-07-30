package rulesync

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/semver"
)

// DefaultAutoInterval is the minimum time between automatic checks.
//
// Rule releases land on a human's schedule, so checking more often than daily
// buys nothing and costs a network round-trip on every scan — plus, from a CI
// fleet behind one NAT, GitHub's unauthenticated rate limit.
const DefaultAutoInterval = 24 * time.Hour

// autocheck.json records when a check was last ATTEMPTED, separately from
// current.json (which records what is installed). The two differ on purpose: a
// check that finds nothing new, or fails outright, must still start the clock,
// or a broken network means a fetch attempt on every single scan.
type autocheck struct {
	CheckedAt string `json:"checkedAt"`
}

func autocheckPath(cacheDir string) string {
	return filepath.Join(rulesDir(cacheDir), "autocheck.json")
}

// lastAutoCheck reports when the last check was attempted. A missing or
// unreadable file reads as "never", which lets a check proceed.
func lastAutoCheck(cacheDir string) (time.Time, bool) {
	b, err := os.ReadFile(autocheckPath(cacheDir)) // #nosec G304 -- our own cache
	if err != nil {
		return time.Time{}, false
	}
	var a autocheck
	if err := json.Unmarshal(b, &a); err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, a.CheckedAt)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func writeAutoCheck(cacheDir string, at time.Time) {
	if err := os.MkdirAll(rulesDir(cacheDir), 0o750); err != nil {
		return // best-effort: failing to record a timestamp must not fail a scan
	}
	b, err := json.MarshalIndent(autocheck{CheckedAt: at.UTC().Format(time.RFC3339)}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(autocheckPath(cacheDir), append(b, '\n'), 0o600)
}

// AutoOptions configures one throttled check. Interval ≤ 0 uses
// DefaultAutoInterval; the embedded Options are passed through to Update.
type AutoOptions struct {
	Options
	Interval time.Duration
}

// AutoResult reports what a check did. All three states are distinguishable so
// a caller can say something truthful without guessing: Checked=false means
// the network was never touched.
type AutoResult struct {
	Checked bool   // a version check actually reached the network
	From    string // the version that was active before ("" = none, embedded packs)
	To      string // the version installed by this call ("" = nothing installed)
	Updated bool   // a newer bundle was fetched and made active
}

// AutoUpdate checks for a newer rule bundle and installs it, at most once per
// Interval. It is deliberately forgiving: every failure short of a corrupt
// install returns a nil error with Updated=false, because a scan must not fail
// because a rules server was unreachable. The signed-bundle guarantees are NOT
// relaxed — installation still runs through Update, so signature and checksum
// verification are identical to an explicit `airom rules update`.
//
// Only a strictly NEWER version is installed. An older or equal remote version
// is left alone, so a rollback on the server never silently downgrades a
// machine that already fetched the newer one.
func AutoUpdate(ctx context.Context, o AutoOptions) (*AutoResult, error) {
	res := &AutoResult{}
	if o.Offline {
		return res, nil
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	interval := o.Interval
	if interval <= 0 {
		interval = DefaultAutoInterval
	}
	if last, ok := lastAutoCheck(o.CacheDir); ok && now().Sub(last) < interval {
		return res, nil // throttled
	}

	// From here on the network is in play, so the clock starts regardless of
	// how this turns out.
	defer writeAutoCheck(o.CacheDir, now())
	res.Checked = true

	_, active, _ := Active(o.CacheDir)
	res.From = active

	latest, err := latestVersion(ctx, o)
	if err != nil {
		return res, nil // unreachable, rate-limited, unsigned — keep what we have
	}
	if !isNewer(latest, active) {
		return res, nil
	}

	up := o.Options
	up.Version = latest // pin to what we verified, not "latest" a second time
	r, err := Update(ctx, up)
	if err != nil {
		// A failed install leaves the cache untouched (Update is atomic), so
		// the previous bundle still stands. Report it as "not updated".
		return res, nil
	}
	res.To, res.Updated = r.Version, true
	return res, nil
}

// latestVersion fetches and VERIFIES the manifest, returning its version.
//
// The signature is checked before the version is read, for the same reason
// Update checks it before reading any other field: an unverified manifest is
// attacker-controlled text, and "is this newer?" is a decision that must not be
// made on it.
func latestVersion(ctx context.Context, o AutoOptions) (string, error) {
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	base := resolveBase(o.Source, "")
	manifestBytes, err := get(ctx, client, base+"/manifest.json")
	if err != nil {
		return "", err
	}
	if !o.InsecureSkipSignature {
		sigBytes, err := get(ctx, client, base+"/manifest.json.sig")
		if err != nil {
			return "", err
		}
		key := o.PublicKey
		if key == nil {
			key = embeddedPublicKey()
		}
		if err := verifyManifest(manifestBytes, sigBytes, key); err != nil {
			return "", err
		}
	}
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return "", err
	}
	if m.Version == "" {
		return "", errors.New("rulesync: manifest declares no version")
	}
	return m.Version, nil
}

// isNewer reports whether remote should replace active.
//
// Both are compared as semver when both parse; a machine with no bundle at all
// (active == "") always accepts. Unparseable versions fall back to plain
// inequality rather than silently refusing to ever update — the bundle channel
// publishes vX.Y.Z, but a mirror is not obliged to.
func isNewer(remote, active string) bool {
	if remote == "" {
		return false
	}
	if active == "" {
		return true
	}
	if semver.IsValid(remote) && semver.IsValid(active) {
		return semver.Compare(remote, active) > 0
	}
	return remote != active
}
