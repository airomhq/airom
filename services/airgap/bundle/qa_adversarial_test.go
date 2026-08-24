package bundle

import (
	"bytes"
	"testing"
)

func TestQA_AdversarialEmptyPayloads(t *testing.T) {
	compiler := NewCompiler(nil)

	pkg := compiler.BuildBundle("empty", "1.0", nil, 0, 0, 0)
	err := compiler.VerifyBundle(pkg)
	if err != nil {
		t.Fatalf("empty bundle should verify cleanly, got %v", err)
	}
}

func TestQA_AdversarialHugePayloadBundle(t *testing.T) {
	compiler := NewCompiler(nil)

	hugeData := bytes.Repeat([]byte("large_rule_pack_data_block_"), 50000) // ~1.5 MB
	payloads := map[string][]byte{
		"huge_pack.bin": hugeData,
	}

	pkg := compiler.BuildBundle("huge", "1.0", payloads, 100, 10, 50000)
	err := compiler.VerifyBundle(pkg)
	if err != nil {
		t.Fatalf("huge payload bundle failed verification: %v", err)
	}
}
