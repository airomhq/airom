package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/airomhq/airom/internal/ociregistry"
)

func TestQA_AdversarialEmptyAndNilMaps(t *testing.T) {
	delta1 := ComputeRuleDiff(nil, nil)
	if delta1.HasChanges() {
		t.Errorf("expected no changes for nil maps")
	}

	hash1 := HashRules(nil)
	hash2 := HashRules(map[string][]byte{})
	if hash1 != hash2 {
		t.Errorf("expected identical hash for nil vs empty map")
	}
}

func TestQA_AdversarialCorruptMirrorManifest(t *testing.T) {
	tmpDir := t.TempDir()
	corruptManifestPath := filepath.Join(tmpDir, "mirror-manifest.json")

	_ = os.WriteFile(corruptManifestPath, []byte("NOT_VALID_JSON{{{"), 0o600)

	_, _, err := ImportMirror(tmpDir)
	if err == nil {
		t.Fatalf("expected error on corrupt mirror manifest")
	}
}

func TestQA_AdversarialMissingLayerFile(t *testing.T) {
	tmpDir := t.TempDir()
	meta := ociregistry.RuleBundleMeta{Name: "missing-layer-bundle", Version: "v1.0"}

	// Export valid mirror then delete layer file
	_ = ExportMirror(tmpDir, []ociregistry.RuleBundleMeta{meta}, map[string][]byte{
		meta.Digest: []byte("placeholder"),
	})

	layerPath := filepath.Join(tmpDir, "missing-layer-bundle.tar.gz")
	_ = os.Remove(layerPath)

	_, _, err := ImportMirror(tmpDir)
	if err == nil {
		t.Fatalf("expected error on missing layer file")
	}
}
