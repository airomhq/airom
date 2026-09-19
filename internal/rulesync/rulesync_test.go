package rulesync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/semver"
)

const tarballName = "airom-rules.tar.gz"

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// signedManifest builds a manifest for tarball at version, signed by priv.
func signedManifest(t *testing.T, version string, tarball []byte, priv ed25519.PrivateKey) (manifest, sig []byte) {
	t.Helper()
	sum := sha256.Sum256(tarball)
	mb, err := json.Marshal(Manifest{Version: version, Tarball: tarballName, SHA256: hex.EncodeToString(sum[:]), RuleCount: 2, PackCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	return mb, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mb)))
}

// serve exposes the three assets at a flat base URL and returns it.
func serve(t *testing.T, manifest, sig, tarball []byte) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(manifest) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(sig) })
	mux.HandleFunc("/"+tarballName, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarball) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestUpdateHappyPathAndActive(t *testing.T) {
	pub, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{
		"frameworks/agno.yaml": "pack: agno\nversion: 1\n",
		"models/openai.yaml":   "pack: openai\nversion: 1\n",
	})
	manifest, sig := signedManifest(t, "v1.0.0", tgz, priv)
	base := serve(t, manifest, sig, tgz)
	cache := t.TempDir()

	res, err := Update(context.Background(), Options{CacheDir: cache, Source: base, PublicKey: pub})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Version != "v1.0.0" || res.PackCount != 1 {
		t.Errorf("result = %+v", res)
	}

	fsys, ver, ok := Active(cache)
	if !ok || ver != "v1.0.0" {
		t.Fatalf("Active = %q, %v", ver, ok)
	}
	b, err := fs.ReadFile(fsys, "frameworks/agno.yaml")
	if err != nil || !strings.Contains(string(b), "pack: agno") {
		t.Errorf("cached pack = %q, %v", b, err)
	}
}

func TestUpdateRejectsBadSignature(t *testing.T) {
	_, priv := genKey(t)
	wrongPub, _ := genKey(t) // verify against a key that did NOT sign
	tgz := makeTarGz(t, map[string]string{"a.yaml": "pack: a\n"})
	manifest, sig := signedManifest(t, "v1", tgz, priv)
	base := serve(t, manifest, sig, tgz)

	_, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: base, PublicKey: wrongPub})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestUpdateRejectsTamperedTarball(t *testing.T) {
	pub, priv := genKey(t)
	good := makeTarGz(t, map[string]string{"a.yaml": "pack: a\n"})
	manifest, sig := signedManifest(t, "v1", good, priv) // manifest commits to good's hash
	evil := makeTarGz(t, map[string]string{"a.yaml": "pack: evil\n"})
	base := serve(t, manifest, sig, evil) // but we serve a different tarball

	_, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: base, PublicKey: pub})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity", err)
	}
}

func TestVerifyManifestNoKeyFailsClosed(t *testing.T) {
	// The absent-key path returns ErrNoSigningKey rather than silently passing.
	if err := verifyManifest([]byte("manifest"), []byte("c2ln"), nil); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", err)
	}
}

func TestEmbeddedKeyIsPresent(t *testing.T) {
	// A real build ships a signing key; a scan-time verification depends on it.
	if embeddedPublicKey() == nil {
		t.Fatal("no ed25519 signing key embedded (airom-rules.pub is a placeholder)")
	}
}

func TestUpdateInsecureSkipStillChecksIntegrity(t *testing.T) {
	_, priv := genKey(t)
	good := makeTarGz(t, map[string]string{"a.yaml": "pack: a\n"})
	manifest, sig := signedManifest(t, "v1", good, priv)

	// Skip signature but keep integrity: a matching tarball installs...
	base := serve(t, manifest, sig, good)
	if _, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: base, InsecureSkipSignature: true}); err != nil {
		t.Fatalf("skip+matching: %v", err)
	}
	// ...a tampered one still fails the checksum.
	evil := makeTarGz(t, map[string]string{"a.yaml": "pack: evil\n"})
	base2 := serve(t, manifest, sig, evil)
	if _, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: base2, InsecureSkipSignature: true}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("skip+tampered: err = %v, want ErrIntegrity", err)
	}
}

func TestUpdateOfflineRefusesBeforeNetwork(t *testing.T) {
	// A source that would fail loudly if dialed; Offline must short-circuit first.
	_, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: "http://127.0.0.1:1/nope", Offline: true})
	if !errors.Is(err, ErrOffline) {
		t.Fatalf("err = %v, want ErrOffline", err)
	}
}

func TestUpdateVersionMismatch(t *testing.T) {
	pub, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{"a.yaml": "pack: a\n"})
	manifest, sig := signedManifest(t, "v1.0.0", tgz, priv)
	base := serve(t, manifest, sig, tgz)

	_, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: base, PublicKey: pub, Version: "v2.0.0"})
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("err = %v, want ErrVersionMismatch", err)
	}
}

func TestActiveMissingCacheIsNotAnError(t *testing.T) {
	if _, _, ok := Active(t.TempDir()); ok {
		t.Error("Active reported a bundle in an empty cache")
	}
}

func TestUntarClampsTraversal(t *testing.T) {
	dest := t.TempDir()
	tgz := makeTarGz(t, map[string]string{
		"../../escape.yaml": "x: 1\n",
		"good.yaml":         "y: 2\n",
	})
	if err := untar(tgz, dest); err != nil {
		t.Fatal(err)
	}
	// The "../" entry must be clamped INSIDE dest, never written to a parent.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.yaml")); !os.IsNotExist(err) {
		t.Fatal("traversal escaped the destination directory")
	}
	if _, err := os.Stat(filepath.Join(dest, "escape.yaml")); err != nil {
		t.Errorf("clamped entry not written inside dest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "good.yaml")); err != nil {
		t.Errorf("good entry missing: %v", err)
	}
}

func TestUntarSkipsNonRegularAndNonYAML(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// a symlink (must be ignored) and a non-yaml file (ignored), plus a real pack.
	if err := tw.WriteHeader(&tar.Header{Name: "link.yaml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "README.md", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte("hi\n"))
	body := "pack: x\n"
	if err := tw.WriteHeader(&tar.Header{Name: "real.yaml", Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write([]byte(body))
	_ = tw.Close()
	_ = gz.Close()

	dest := t.TempDir()
	if err := untar(buf.Bytes(), dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link.yaml")); !os.IsNotExist(err) {
		t.Error("symlink entry was written")
	}
	if _, err := os.Stat(filepath.Join(dest, "README.md")); !os.IsNotExist(err) {
		t.Error("non-yaml entry was written")
	}
	if _, err := os.Stat(filepath.Join(dest, "real.yaml")); err != nil {
		t.Errorf("real pack missing: %v", err)
	}
}

func TestUntarSkipsDotfiles(t *testing.T) {
	// macOS tar injects AppleDouble "._name" siblings; they end in .yaml but are
	// binary and would break the loader. They must be dropped, not extracted.
	dest := t.TempDir()
	tgz := makeTarGz(t, map[string]string{
		"frameworks/._agno.yaml": "\x00\x01binary AppleDouble junk\n",
		"frameworks/agno.yaml":   "pack: agno\nversion: 1\n",
	})
	if err := untar(tgz, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "frameworks", "._agno.yaml")); !os.IsNotExist(err) {
		t.Error("AppleDouble dotfile was extracted")
	}
	if _, err := os.Stat(filepath.Join(dest, "frameworks", "agno.yaml")); err != nil {
		t.Errorf("real pack missing: %v", err)
	}
}

func TestUntarRejectsEmptyBundle(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{"README.md": "no packs here\n"})
	if err := untar(tgz, t.TempDir()); err == nil {
		t.Error("untar accepted a bundle with no rule packs")
	}
}

// signedManifestFull is signedManifest with the fields item 4 added: a build
// time and a minimum-airom floor.
func signedManifestFull(t *testing.T, version, createdAt, minAirom string, tarball []byte, priv ed25519.PrivateKey) (manifest, sig []byte) {
	t.Helper()
	sum := sha256.Sum256(tarball)
	mb, err := json.Marshal(Manifest{
		Version: version, Tarball: tarballName, SHA256: hex.EncodeToString(sum[:]),
		RuleCount: 2, PackCount: 1, CreatedAt: createdAt, MinAirom: minAirom,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mb, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mb)))
}

// updateWith runs one Update against a served bundle carrying createdAt and
// minAirom, as the build named by selfVersion.
func updateWith(t *testing.T, createdAt, minAirom, selfVersion string, now time.Time) (*Result, string, error) {
	t.Helper()
	pub, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{"models/openai.yaml": "pack: openai\nversion: 1\n"})
	manifest, sig := signedManifestFull(t, "v1.0.0", createdAt, minAirom, tgz, priv)
	base := serve(t, manifest, sig, tgz)
	cache := t.TempDir()
	res, err := Update(context.Background(), Options{
		CacheDir: cache, Source: base, PublicKey: pub,
		SelfVersion: selfVersion,
		Now:         func() time.Time { return now },
	})
	return res, cache, err
}

// TestMinAiromFloorRefusesAnOlderBuild: a bundle that needs a newer airom is
// refused AT INSTALL. Without this it installs, and then every scan afterwards
// fails to parse it, warns, and silently falls back to the embedded packs — a
// daily symptom a long way from its cause.
func TestMinAiromFloorRefusesAnOlderBuild(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	_, cache, err := updateWith(t, "", "v0.9.0", "0.4.6", now)
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("err = %v, want ErrIncompatible", err)
	}
	if !strings.Contains(err.Error(), "v0.9.0") || !strings.Contains(err.Error(), "0.4.6") {
		t.Errorf("error should name both versions, got: %v", err)
	}
	// Fail-closed: nothing installed.
	if _, _, ok := Active(cache); ok {
		t.Error("a refused bundle must leave the cache untouched")
	}
}

func TestMinAiromFloorAcceptsEqualAndNewer(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, self := range []string{"v0.9.0", "0.9.0", "v0.9.1", "v1.2.0"} {
		if _, _, err := updateWith(t, "", "v0.9.0", self, now); err != nil {
			t.Errorf("self %q against floor v0.9.0: %v", self, err)
		}
	}
}

// A version string that cannot be compared cannot be gated: "dev" is not a
// point on the line, and refusing it would break every `go build` the moment a
// floor is published. A `git describe` version is a different case — it IS
// valid semver (the suffix is a prerelease), so it is comparable, and a
// from-source build genuinely older than the floor is held to it like any
// other. Both halves are asserted here because the distinction is the whole
// design: skip what is unknown, gate what is known.
func TestMinAiromFloorGatesOnlyComparableVersions(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	for _, self := range []string{"", "dev"} {
		if _, _, err := updateWith(t, "", "v9.9.9", self, now); err != nil {
			t.Errorf("self %q is not comparable and must not be gated: %v", self, err)
		}
	}

	describe := "v0.4.6-4-gabc1234-dirty"
	if !semver.IsValid(describe) {
		t.Fatalf("precondition: %q should be valid semver, or this test proves nothing", describe)
	}
	if _, _, err := updateWith(t, "", "v9.9.9", describe, now); !errors.Is(err, ErrIncompatible) {
		t.Errorf("self %q is comparable and below the floor; err = %v, want ErrIncompatible", describe, err)
	}
}

// TestCreatedAtRejectsTheImpossible: a build time in the future beyond clock
// skew, or one that is not RFC 3339, means the manifest is wrong — and it is
// inside the signed bytes, so it is the publisher's claim, not noise in transit.
func TestCreatedAtRejectsTheImpossible(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, createdAt string }{
		{"far future", now.Add(72 * time.Hour).Format(time.RFC3339)},
		{"not rfc3339", "20 September 2026"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cache, err := updateWith(t, tc.createdAt, "", "v0.4.6", now)
			if !errors.Is(err, ErrManifest) {
				t.Fatalf("err = %v, want ErrManifest", err)
			}
			if _, _, ok := Active(cache); ok {
				t.Error("a refused bundle must leave the cache untouched")
			}
		})
	}
}

// Skew inside the allowance, and a bundle with no build time at all (published
// before the field existed), both install.
func TestCreatedAtToleratesSkewAndAbsence(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct{ name, createdAt string }{
		{"slightly ahead", now.Add(2 * time.Hour).Format(time.RFC3339)},
		{"absent", ""},
		{"old but fine", now.Add(-365 * 24 * time.Hour).Format(time.RFC3339)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := updateWith(t, tc.createdAt, "", "v0.4.6", now); err != nil {
				t.Errorf("Update: %v", err)
			}
		})
	}
}

// TestCreatedAtIsRecorded: the build time has to survive the install, or a scan
// months later still cannot say how old its rules are.
func TestCreatedAtIsRecorded(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	built := "2026-09-18T10:00:00Z"
	res, cache, err := updateWith(t, built, "", "v0.4.6", now)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.CreatedAt != built {
		t.Errorf("Result.CreatedAt = %q, want %q", res.CreatedAt, built)
	}
	b, err := os.ReadFile(filepath.Join(cache, "rules", "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct{ CreatedAt, FetchedAt string }
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if c.CreatedAt != built {
		t.Errorf("current.json createdAt = %q, want %q", c.CreatedAt, built)
	}
	// The two are different facts: when the publisher built it, and when this
	// machine fetched it. Collapsing them would make a year-old bundle fetched
	// today look fresh.
	if c.FetchedAt == c.CreatedAt {
		t.Errorf("fetchedAt must not be the build time: both %q", c.FetchedAt)
	}
}
