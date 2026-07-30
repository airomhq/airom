package rulesync

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// serveCounting is serve() plus a hit counter, so a test can prove the network
// was NOT reached rather than only that the result looked right.
func serveCounting(t *testing.T, manifest, sig, tarball []byte, hits *atomic.Int64) string {
	t.Helper()
	mux := http.NewServeMux()
	count := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { hits.Add(1); h(w, r) }
	}
	mux.HandleFunc("/manifest.json", count(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(manifest) }))
	mux.HandleFunc("/manifest.json.sig", count(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(sig) }))
	mux.HandleFunc("/"+tarballName, count(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarball) }))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func autoOpts(cache, base string, pub ed25519.PublicKey, now time.Time) AutoOptions {
	return AutoOptions{
		Options: Options{
			CacheDir:  cache,
			Source:    base,
			PublicKey: pub,
			Now:       func() time.Time { return now },
		},
	}
}

func TestAutoUpdateInstallsWhenNoneCached(t *testing.T) {
	pub, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{"frameworks/agno.yaml": "pack: agno\nversion: 1\n"})
	manifest, sig := signedManifest(t, "v1.0.0", tgz, priv)
	base := serve(t, manifest, sig, tgz)
	cache := t.TempDir()

	res, err := AutoUpdate(context.Background(), autoOpts(cache, base, pub, time.Now()))
	if err != nil {
		t.Fatalf("AutoUpdate: %v", err)
	}
	if !res.Checked || !res.Updated || res.To != "v1.0.0" || res.From != "" {
		t.Fatalf("result = %+v, want checked+updated to v1.0.0 from nothing", res)
	}
	if _, ver, ok := Active(cache); !ok || ver != "v1.0.0" {
		t.Errorf("Active = %q, %v", ver, ok)
	}
}

func TestAutoUpdateThrottlesWithinInterval(t *testing.T) {
	pub, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{"frameworks/agno.yaml": "pack: agno\nversion: 1\n"})
	manifest, sig := signedManifest(t, "v1.0.0", tgz, priv)
	var hits atomic.Int64
	base := serveCounting(t, manifest, sig, tgz, &hits)
	cache := t.TempDir()
	t0 := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

	if _, err := AutoUpdate(context.Background(), autoOpts(cache, base, pub, t0)); err != nil {
		t.Fatal(err)
	}
	after := hits.Load()
	if after == 0 {
		t.Fatal("first call made no requests — the test would prove nothing")
	}

	// An hour later: inside the 24h window, so nothing may be dialed at all.
	res, err := AutoUpdate(context.Background(), autoOpts(cache, base, pub, t0.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked {
		t.Error("Checked = true within the throttle window")
	}
	if got := hits.Load(); got != after {
		t.Errorf("made %d extra request(s) while throttled; want 0", got-after)
	}

	// Past the window, it checks again.
	res, err = AutoUpdate(context.Background(), autoOpts(cache, base, pub, t0.Add(25*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Checked {
		t.Error("Checked = false after the throttle window elapsed")
	}
}

func TestAutoUpdateIgnoresOlderAndEqualRemote(t *testing.T) {
	pub, priv := genKey(t)
	newTgz := makeTarGz(t, map[string]string{"frameworks/agno.yaml": "pack: agno\nversion: 2\n"})
	newManifest, newSig := signedManifest(t, "v2.0.0", newTgz, priv)
	cache := t.TempDir()
	t0 := time.Now()

	// Land v2.0.0 first.
	if _, err := Update(context.Background(), Options{
		CacheDir: cache, Source: serve(t, newManifest, newSig, newTgz), PublicKey: pub, Version: "v2.0.0",
	}); err != nil {
		t.Fatal(err)
	}

	for _, remote := range []string{"v1.9.9", "v2.0.0"} {
		t.Run(remote, func(t *testing.T) {
			oldTgz := makeTarGz(t, map[string]string{"frameworks/agno.yaml": "pack: agno\nversion: 1\n"})
			m, s := signedManifest(t, remote, oldTgz, priv)
			base := serve(t, m, s, oldTgz)
			// Fresh clock each time so the throttle never masks the result.
			o := autoOpts(cache, base, pub, t0.Add(48*time.Hour))
			res, err := AutoUpdate(context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			if res.Updated {
				t.Errorf("installed %s over the newer v2.0.0", remote)
			}
			if _, ver, _ := Active(cache); ver != "v2.0.0" {
				t.Errorf("active = %q, want v2.0.0 to stand", ver)
			}
		})
	}
}

func TestAutoUpdateOfflineNeverDials(t *testing.T) {
	pub, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{"frameworks/agno.yaml": "pack: agno\nversion: 1\n"})
	manifest, sig := signedManifest(t, "v1.0.0", tgz, priv)
	var hits atomic.Int64
	base := serveCounting(t, manifest, sig, tgz, &hits)

	o := autoOpts(t.TempDir(), base, pub, time.Now())
	o.Offline = true
	res, err := AutoUpdate(context.Background(), o)
	if err != nil {
		t.Fatalf("offline must not be an error for auto-update: %v", err)
	}
	if res.Checked || res.Updated {
		t.Errorf("result = %+v, want no check", res)
	}
	if hits.Load() != 0 {
		t.Errorf("dialed %d time(s) while offline", hits.Load())
	}
}

func TestAutoUpdateUnreachableServerIsNotAnError(t *testing.T) {
	pub, _ := genKey(t)
	// A port nothing is listening on: every fetch fails.
	o := autoOpts(t.TempDir(), "http://127.0.0.1:1/nope", pub, time.Now())
	res, err := AutoUpdate(context.Background(), o)
	if err != nil {
		t.Fatalf("a scan must not fail because the rules server is down: %v", err)
	}
	if res.Updated {
		t.Error("Updated = true against a dead server")
	}
}

func TestAutoUpdateRejectsUnsignedManifest(t *testing.T) {
	pub, _ := genKey(t)      // this key verifies nothing that follows
	_, attacker := genKey(t) // a DIFFERENT key signs the manifest
	tgz := makeTarGz(t, map[string]string{"frameworks/evil.yaml": "pack: evil\nversion: 1\n"})
	manifest, sig := signedManifest(t, "v9.9.9", tgz, attacker)
	cache := t.TempDir()

	res, err := AutoUpdate(context.Background(), autoOpts(cache, serve(t, manifest, sig, tgz), pub, time.Now()))
	if err != nil {
		t.Fatalf("AutoUpdate: %v", err)
	}
	if res.Updated {
		t.Fatal("installed a bundle whose manifest was signed by an untrusted key")
	}
	if _, _, ok := Active(cache); ok {
		t.Fatal("an unverified bundle became active")
	}
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		remote, active string
		want           bool
	}{
		{"v0.1.5", "v0.1.4", true},
		{"v0.2.0", "v0.1.9", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.1.4", "v0.1.5", false}, // never auto-downgrade
		{"v0.1.5", "v0.1.5", false},
		{"v0.1.5", "", true}, // nothing cached yet
		{"", "v0.1.5", false},
		{"", "", false},
		// Unparseable versions fall back to inequality rather than freezing.
		{"nightly-2", "nightly-1", true},
		{"nightly-1", "nightly-1", false},
	}
	for _, c := range cases {
		if got := isNewer(c.remote, c.active); got != c.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", c.remote, c.active, got, c.want)
		}
	}
}
