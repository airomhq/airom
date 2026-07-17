package imagesource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSplitDigestRejectsTraversal locks the security boundary: digest
// components are joined onto the filesystem in parseOCILayoutDir, so
// splitDigest must reject any component carrying a path separator or other
// non-canonical byte. (Phase 10 review, sources-security finding.)
func TestSplitDigestRejectsTraversal(t *testing.T) {
	bad := []string{
		"sha256:../../../../../../etc/passwd",
		"sha256:..",
		"sha256:../abc",
		"sha256:abc/../../def",
		`sha256:..\..\windows`,
		"../../../../etc:passwd", // traversal smuggled through the algorithm half
		"sha256:AB/CD",
		"sha256:zzzz", // non-hex encoded value
		"sha256:",     // empty encoded value
		":deadbeef",   // empty algorithm
		"deadbeef",    // no separator
		"sha256:dead beef",
	}
	for _, d := range bad {
		if _, _, ok := splitDigest(d); ok {
			t.Errorf("splitDigest(%q) = ok; want rejected", d)
		}
	}

	good := []struct{ in, alg, hex string }{
		{
			"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{"sha512:ABCDEF0123456789", "sha512", "ABCDEF0123456789"},
	}
	for _, g := range good {
		alg, hexv, ok := splitDigest(g.in)
		if !ok || alg != g.alg || hexv != g.hex {
			t.Errorf("splitDigest(%q) = (%q,%q,%v); want (%q,%q,true)", g.in, alg, hexv, ok, g.alg, g.hex)
		}
	}
}

// TestParseOCILayoutDirRejectsTraversalDigest proves the end-to-end path: a
// crafted OCI image-layout directory whose manifest descriptor digest points
// outside blobs/ must be refused, never read off the host filesystem.
func TestParseOCILayoutDirRejectsTraversalDigest(t *testing.T) {
	dir := t.TempDir()

	// Plant a decoy the malicious digest would resolve to, to be certain we
	// refuse rather than silently read it.
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// index.json with a manifest descriptor whose digest escapes blobs/ via
	// '..' segments back up to secret.txt (…/blobs/sha256/../../secret.txt).
	idx := `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:../../secret.txt","size":2}]}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(idx), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := (&Source{}).parseOCILayoutDir(dir)
	if err == nil {
		t.Fatal("parseOCILayoutDir accepted a traversal digest; want an error")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("error %q does not mention the bad digest", err)
	}
}
