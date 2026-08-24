package ociregistry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// PackRules packs a collection of rule files into an in-memory OCI artifact layer.
func PackRules(meta RuleBundleMeta, rules map[string][]byte) (layerBytes []byte, manifestBytes []byte, err error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	meta.CreatedAt = time.Now().UTC()
	meta.RuleCount = len(rules)

	for filename, content := range rules {
		cleanName := filepath.ToSlash(filepath.Clean(filename))
		cleanName = strings.TrimPrefix(cleanName, "/")
		if strings.HasPrefix(cleanName, "../") || cleanName == ".." {
			return nil, nil, fmt.Errorf("illegal relative path in rule pack: %s", filename)
		}

		hdr := &tar.Header{
			Name:     cleanName,
			Mode:     0o600,
			Size:     int64(len(content)),
			ModTime:  meta.CreatedAt,
			Typeflag: tar.TypeReg,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, fmt.Errorf("tar write header: %w", err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, nil, fmt.Errorf("tar write content: %w", err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, nil, err
	}

	layerBytes = buf.Bytes()
	meta.TotalBytes = int64(len(layerBytes))

	layerHash := sha256.Sum256(layerBytes)
	layerDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(layerHash[:]))
	meta.Digest = layerDigest

	configData, err := json.Marshal(meta)
	if err != nil {
		return nil, nil, err
	}
	cfgHash := sha256.Sum256(configData)
	cfgDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(cfgHash[:]))

	manifest := OCIManifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config: OCIDescriptor{
			MediaType: MediaTypeRulePackConfig,
			Digest:    cfgDigest,
			Size:      int64(len(configData)),
		},
		Layers: []OCIDescriptor{
			{
				MediaType: MediaTypeRulePackLayer,
				Digest:    layerDigest,
				Size:      int64(len(layerBytes)),
			},
		},
		Annotations: map[string]string{
			"org.opencontainers.image.title":       meta.Name,
			"org.opencontainers.image.version":     meta.Version,
			"org.opencontainers.image.created":     meta.CreatedAt.Format(time.RFC3339),
			"org.opencontainers.image.description": meta.Description,
		},
	}

	manifestBytes, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, nil, err
	}

	return layerBytes, manifestBytes, nil
}

// UnpackRules unpacks an OCI layer tarball into rule memory safely with path traversal protection.
func UnpackRules(layerBytes []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(layerBytes))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	rules := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}

		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))
		cleanName = strings.TrimPrefix(cleanName, "/")
		if strings.HasPrefix(cleanName, "../") || cleanName == ".." {
			return nil, fmt.Errorf("path traversal attempt rejected: %s", hdr.Name)
		}

		if hdr.Typeflag == tar.TypeReg {
			var content bytes.Buffer
			if _, err := io.Copy(&content, tr); err != nil {
				return nil, fmt.Errorf("tar read content: %w", err)
			}
			rules[cleanName] = content.Bytes()
		}
	}

	// Drain gzip stream to trigger trailing CRC32 checksum validation
	if _, err := io.Copy(io.Discard, gr); err != nil {
		return nil, fmt.Errorf("gzip checksum error: %w", err)
	}

	return rules, nil
}
