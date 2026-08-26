package signatures

import (
	"testing"
)

func TestQA_AdversarialForgedKeyID(t *testing.T) {
	engine := NewEngine()

	key1, _ := engine.GenerateKeyPair(SchemeMLDSA65)
	key2, _ := engine.GenerateKeyPair(SchemeMLDSA65)

	sig, _ := engine.SignModel(key1, "sha3-512:digest")

	// Verify using key2 (different key ID)
	res := engine.VerifySignature(key2, sig, "sha3-512:digest")
	if res.Valid {
		t.Fatalf("SECURITY VIOLATION: signature validated with wrong key ID")
	}
}

func TestQA_AdversarialBitFlippedSignature(t *testing.T) {
	engine := NewEngine()

	key, _ := engine.GenerateKeyPair(SchemeMLDSA87)
	sig, _ := engine.SignModel(key, "sha3-512:digest")

	// Flip last bit of signature
	sig.SignatureBytes[len(sig.SignatureBytes)-1] ^= 0x01

	res := engine.VerifySignature(key, sig, "sha3-512:digest")
	if res.Valid {
		t.Fatalf("SECURITY VIOLATION: bit-flipped signature validated as true")
	}
}
