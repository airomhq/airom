package ociregistry

import (
	"context"
	"testing"
)

func TestOCIRulePack_Roundtrip(t *testing.T) {
	client := NewClient(RegistryConfig{})

	meta := RuleBundleMeta{
		Name:        "enterprise-compliance-rules",
		Version:     "v1.0.0",
		Description: "Custom rules for Colorado and NYC AI governance",
		Author:      "Security Team",
	}

	rules := map[string][]byte{
		"rules/custom/openai.yaml":    []byte("id: rules/custom/openai\npattern: gpt-4o"),
		"rules/custom/anthropic.yaml": []byte("id: rules/custom/anthropic\npattern: claude-3-5"),
	}

	layerBytes, manifestBytes, err := PackRules(meta, rules)
	if err != nil {
		t.Fatalf("failed to pack rules: %v", err)
	}

	repoRef := "ghcr.io/org/enterprise-ai-rules:v1.0.0"
	if err := client.Push(context.Background(), repoRef, layerBytes, manifestBytes); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	pulledRules, manifest, err := client.Pull(context.Background(), repoRef)
	if err != nil {
		t.Fatalf("pull failed: %v", err)
	}

	if manifest.Annotations["org.opencontainers.image.title"] != "enterprise-compliance-rules" {
		t.Errorf("manifest title mismatch: %v", manifest.Annotations)
	}

	if len(pulledRules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(pulledRules))
	}

	if string(pulledRules["rules/custom/openai.yaml"]) != string(rules["rules/custom/openai.yaml"]) {
		t.Errorf("rule content corrupted")
	}
}

func TestOCIRulePack_DigestVerification(t *testing.T) {
	meta := RuleBundleMeta{Name: "test-pack", Version: "v1.0"}
	rules := map[string][]byte{"test.yaml": []byte("key: value")}

	layerBytes, _, err := PackRules(meta, rules)
	if err != nil {
		t.Fatalf("pack failed: %v", err)
	}

	// Tamper layer byte
	tampered := make([]byte, len(layerBytes))
	copy(tampered, layerBytes)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = UnpackRules(tampered)
	if err == nil {
		t.Fatalf("expected unpack error on tampered gzip data")
	}
}
