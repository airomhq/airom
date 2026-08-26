package signatures

import (
	"testing"
)

func TestPQC_SignAndVerifyModel(t *testing.T) {
	engine := NewEngine()

	key, err := engine.GenerateKeyPair(SchemeMLDSA87)
	if err != nil || key == nil {
		t.Fatalf("failed to generate ML-DSA-87 keypair: %v", err)
	}

	modelDigest := "sha3-512:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	sig, err := engine.SignModel(key, modelDigest)
	if err != nil || sig == nil {
		t.Fatalf("failed to sign model: %v", err)
	}

	res := engine.VerifySignature(key, sig, modelDigest)
	if !res.Valid {
		t.Fatalf("expected valid PQC signature, failed: %s", res.Reason)
	}
}

func TestPQC_TamperedDigestFails(t *testing.T) {
	engine := NewEngine()

	key, _ := engine.GenerateKeyPair(SchemeSLHDSA128)
	sig, _ := engine.SignModel(key, "sha3-512:original_hash")

	tamperedDigest := "sha3-512:tampered_hash"
	res := engine.VerifySignature(key, sig, tamperedDigest)
	if res.Valid {
		t.Fatalf("SECURITY VIOLATION: signature verified over tampered digest")
	}
}
