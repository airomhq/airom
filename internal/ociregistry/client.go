package ociregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

// Client interacts with OCI compliant container and artifact registries.
type Client struct {
	cfg   RegistryConfig
	store map[string][]byte // in-memory local cache/mirror: digest/tag -> bytes
	mu    sync.RWMutex
}

// NewClient constructs an OCI registry client.
func NewClient(cfg RegistryConfig) *Client {
	if cfg.RegistryHost == "" {
		cfg.RegistryHost = "ghcr.io"
	}
	return &Client{
		cfg:   cfg,
		store: make(map[string][]byte),
	}
}

// Push stores a rule pack layer and its manifest under a repository reference tag.
func (c *Client) Push(ctx context.Context, repoRef string, layerBytes []byte, manifestBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	layerHash := sha256.Sum256(layerBytes)
	layerDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(layerHash[:]))

	manifestHash := sha256.Sum256(manifestBytes)
	manifestDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(manifestHash[:]))

	// Store layer blob and manifest
	c.store[layerDigest] = layerBytes
	c.store[manifestDigest] = manifestBytes
	c.store[repoRef] = manifestBytes

	return nil
}

// Pull retrieves a rule pack manifest and extracts its rules.
func (c *Client) Pull(ctx context.Context, repoRef string) (map[string][]byte, *OCIManifest, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	manifestBytes, ok := c.store[repoRef]
	if !ok {
		return nil, nil, fmt.Errorf("artifact not found in registry: %s", repoRef)
	}

	var manifest OCIManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, nil, fmt.Errorf("malformed manifest: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, nil, fmt.Errorf("manifest has 0 layers")
	}

	layerDigest := manifest.Layers[0].Digest
	layerBytes, ok := c.store[layerDigest]
	if !ok {
		return nil, nil, fmt.Errorf("layer blob not found: %s", layerDigest)
	}

	// Verify layer digest
	actualHash := sha256.Sum256(layerBytes)
	actualDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(actualHash[:]))
	if actualDigest != layerDigest {
		return nil, nil, fmt.Errorf("layer digest mismatch: expected %s, got %s", layerDigest, actualDigest)
	}

	rules, err := UnpackRules(layerBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack rules: %w", err)
	}

	return rules, &manifest, nil
}
