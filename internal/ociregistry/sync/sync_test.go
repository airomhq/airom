package sync

import (
	"path/filepath"
	"testing"

	"github.com/airomhq/airom/internal/ociregistry"
)

func TestComputeRuleDiff(t *testing.T) {
	local := map[string][]byte{
		"rules/unchanged.yaml": []byte("pattern: keep"),
		"rules/modified.yaml":  []byte("pattern: old_version"),
		"rules/deleted.yaml":   []byte("pattern: to_remove"),
	}

	remote := map[string][]byte{
		"rules/unchanged.yaml": []byte("pattern: keep"),
		"rules/modified.yaml":  []byte("pattern: new_version"),
		"rules/added.yaml":     []byte("pattern: brand_new"),
	}

	delta := ComputeRuleDiff(local, remote)

	if !delta.HasChanges() {
		t.Fatalf("expected changes in delta")
	}

	if len(delta.Added) != 1 || string(delta.Added["rules/added.yaml"]) != "pattern: brand_new" {
		t.Errorf("added mismatch: %+v", delta.Added)
	}

	if len(delta.Modified) != 1 || string(delta.Modified["rules/modified.yaml"]) != "pattern: new_version" {
		t.Errorf("modified mismatch: %+v", delta.Modified)
	}

	if len(delta.Removed) != 1 || delta.Removed[0] != "rules/deleted.yaml" {
		t.Errorf("removed mismatch: %+v", delta.Removed)
	}
}

func TestMirror_ExportAndImport(t *testing.T) {
	tmpDir := t.TempDir()

	meta := ociregistry.RuleBundleMeta{Name: "bundle-1", Version: "v1.0"}
	rules := map[string][]byte{
		"rules/m1.yaml": []byte("pattern: gpt-4o"),
	}

	layerBytes, _, err := ociregistry.PackRules(meta, rules)
	if err != nil {
		t.Fatalf("failed to pack: %v", err)
	}

	bundles := []ociregistry.RuleBundleMeta{meta}
	bundleLayers := map[string][]byte{
		meta.Digest: layerBytes,
	}

	mirrorDir := filepath.Join(tmpDir, "airgap-mirror")
	if err := ExportMirror(mirrorDir, bundles, bundleLayers); err != nil {
		t.Fatalf("export mirror failed: %v", err)
	}

	importedRules, manifest, err := ImportMirror(mirrorDir)
	if err != nil {
		t.Fatalf("import mirror failed: %v", err)
	}

	if len(manifest.Bundles) != 1 || manifest.Bundles[0].Name != "bundle-1" {
		t.Errorf("manifest mismatch: %+v", manifest)
	}

	if string(importedRules["rules/m1.yaml"]) != "pattern: gpt-4o" {
		t.Errorf("imported rules mismatch: %+v", importedRules)
	}
}

func TestMirror_MissingFileHandling(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "does-not-exist")

	_, _, err := ImportMirror(nonExistent)
	if err == nil {
		t.Fatalf("expected error on non-existent mirror dir")
	}
}
