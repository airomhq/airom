package stego

import (
	"crypto/rand"
	"testing"
)

func TestQA_AdversarialEmptyAndTinyCarriers(t *testing.T) {
	extractor := NewExtractor()

	// Empty carrier
	_, detected := extractor.ExtractLSBBytes("layer", nil)
	if detected {
		t.Errorf("expected false on nil carrier")
	}

	// Tiny carrier (< 64 bytes)
	_, detected = extractor.ExtractLSBBytes("layer", make([]byte, 10))
	if detected {
		t.Errorf("expected false on tiny carrier")
	}
}

func TestQA_AdversarialCorruptedHighEntropyStreams(t *testing.T) {
	extractor := NewExtractor()

	// Pure cryptographic noise
	noise := make([]byte, 1024)
	_, _ = rand.Read(noise)

	// Scanning pure noise must not crash or deadlock
	finding, detected := extractor.ExtractLSBBytes("noise_layer", noise)
	if detected && finding.EntropyScore < 7.0 {
		t.Errorf("noise flagged with low entropy: %f", finding.EntropyScore)
	}
}
