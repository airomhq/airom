package sync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/airomhq/airom/internal/ociregistry"
)

// MirrorManifest index file stored at root of air-gapped mirror directory.
type MirrorManifest struct {
	CreatedAt time.Time                    `json:"createdAt"`
	Bundles   []ociregistry.RuleBundleMeta `json:"bundles"`
}

// ExportMirror writes an offline rule bundle directory ready for air-gapped deployment.
func ExportMirror(destDir string, bundles []ociregistry.RuleBundleMeta, bundleLayers map[string][]byte) error {
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		return fmt.Errorf("mkdir mirror dest: %w", err)
	}

	manifest := MirrorManifest{
		CreatedAt: time.Now().UTC(),
		Bundles:   bundles,
	}

	for _, b := range bundles {
		layerData, ok := bundleLayers[b.Digest]
		if !ok {
			return fmt.Errorf("layer data missing for bundle: %s", b.Digest)
		}
		layerPath := filepath.Join(destDir, fmt.Sprintf("%s.tar.gz", b.Name))
		if err := os.WriteFile(layerPath, layerData, 0o600); err != nil {
			return fmt.Errorf("write layer file: %w", err)
		}
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	manifestPath := filepath.Join(destDir, "mirror-manifest.json")
	return os.WriteFile(manifestPath, manifestBytes, 0o600)
}

// ImportMirror loads all rule bundles from an air-gapped offline mirror directory.
func ImportMirror(mirrorDir string) (map[string][]byte, *MirrorManifest, error) {
	manifestPath := filepath.Join(mirrorDir, "mirror-manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read mirror manifest: %w", err)
	}

	var manifest MirrorManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("unmarshal mirror manifest: %w", err)
	}

	allRules := make(map[string][]byte)
	for _, b := range manifest.Bundles {
		layerPath := filepath.Join(mirrorDir, fmt.Sprintf("%s.tar.gz", b.Name))
		layerData, err := os.ReadFile(layerPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read bundle layer %s: %w", b.Name, err)
		}

		rules, err := ociregistry.UnpackRules(layerData)
		if err != nil {
			return nil, nil, fmt.Errorf("unpack bundle %s: %w", b.Name, err)
		}

		for k, v := range rules {
			allRules[k] = v
		}
	}

	return allRules, &manifest, nil
}
