package ociregistry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
)

func TestQA_AdversarialTarPathTraversal(t *testing.T) {
	// Construct malicious tarball with path traversal entries
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	traversalPaths := []string{
		"../../etc/shadow",
		"/etc/passwd",
		"rules/../../../sensitive.key",
	}

	for _, p := range traversalPaths {
		_ = tw.WriteHeader(&tar.Header{
			Name:     p,
			Size:     4,
			Typeflag: tar.TypeReg,
		})
		_, _ = tw.Write([]byte("evil"))
	}
	_ = tw.Close()
	_ = gw.Close()

	// Attempt unpack — must fail closed and reject path traversal
	rules, err := UnpackRules(buf.Bytes())
	if err == nil {
		t.Fatalf("expected error unpacking traversal paths, but succeeded with %d rules", len(rules))
	}
}

func TestQA_AdversarialCorruptedLayerGzip(t *testing.T) {
	corruptBytes := []byte{0x1f, 0x8b, 0x08, 0x00, 0x99, 0x99, 0x99} // truncated gzip

	_, err := UnpackRules(corruptBytes)
	if err == nil {
		t.Fatalf("expected error unpacking corrupt gzip stream")
	}
}

func TestQA_AdversarialNonExistentArtifact(t *testing.T) {
	client := NewClient(RegistryConfig{})

	_, _, err := client.Pull(context.Background(), "ghcr.io/org/nonexistent:latest")
	if err == nil {
		t.Fatalf("expected error pulling nonexistent artifact")
	}
}
