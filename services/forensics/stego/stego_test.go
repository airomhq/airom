package stego

import (
	"strings"
	"testing"
)

func TestStego_EmbedAndExtractSecretText(t *testing.T) {
	extractor := NewExtractor()

	secretText := "EXFILTRATED_API_KEY_sk_secret_1234567890abcdef"
	carrier := make([]byte, 1024)
	for i := range carrier {
		carrier[i] = byte(i % 256)
	}

	stegoWeights := EmbedLSBBytes([]byte(secretText), carrier)
	finding, detected := extractor.ExtractLSBBytes("model.layers.0.q_proj", stegoWeights)

	if !detected {
		t.Fatalf("expected stego payload detected")
	}

	if !strings.HasPrefix(finding.PayloadUTF8, secretText) {
		t.Errorf("extracted payload mismatch: %s vs %s", finding.PayloadUTF8, secretText)
	}

	if finding.SHA256 == "" {
		t.Errorf("missing SHA256 hash in finding")
	}
}

func TestStego_CleanCarrierNoFalsePositive(t *testing.T) {
	extractor := NewExtractor()

	// Natural weights with LSB = 0
	carrier := make([]byte, 256)
	for i := range carrier {
		carrier[i] = byte((i * 2) % 256)
	}

	_, detected := extractor.ExtractLSBBytes("clean_layer", carrier)
	if detected {
		t.Errorf("clean carrier triggered false positive detection")
	}
}
