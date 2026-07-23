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

func TestUpdateNoKeyFailsClosed(t *testing.T) {
	_, priv := genKey(t)
	tgz := makeTarGz(t, map[string]string{"a.yaml": "pack: a\n"})
	manifest, sig := signedManifest(t, "v1", tgz, priv)
	base := serve(t, manifest, sig, tgz)

	// No injected key and the embedded key is a placeholder → cannot verify.
	_, err := Update(context.Background(), Options{CacheDir: t.TempDir(), Source: base})
	if !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", err)
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

func TestUntarRejectsEmptyBundle(t *testing.T) {
	tgz := makeTarGz(t, map[string]string{"README.md": "no packs here\n"})
	if err := untar(tgz, t.TempDir()); err == nil {
		t.Error("untar accepted a bundle with no rule packs")
	}
}
