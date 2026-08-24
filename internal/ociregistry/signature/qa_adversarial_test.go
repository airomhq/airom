package signature

import (
	"testing"
	"time"
)

func TestQA_AdversarialForgedPublicKeySubstitution(t *testing.T) {
	legitKey, _ := GenerateKeyPair()
	attackerKey, _ := GenerateKeyPair()

	payload := []byte("critical_compliance_rules")
	env, err := SignRuleBundle(payload, legitKey, "legit@corp.com", "issuer", 1*time.Hour)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Substitute public key with attacker's key (signature was created with legitKey)
	env.PublicKey = string(attackerKey.PublicKey) // Invalid format / mismatched key

	verifier := NewVerifier(VerificationPolicy{})
	if err := verifier.Verify(payload, env); err == nil {
		t.Fatalf("expected verification failure on substituted key, got nil")
	}
}

func TestQA_AdversarialBitFlippedSignature(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	payload := []byte("rule_bundle")

	env, _ := SignRuleBundle(payload, keyPair, "signer@test.com", "issuer", 1*time.Hour)

	// Bit-flip signature hex string
	sigRunes := []rune(env.Signature)
	if sigRunes[0] == 'a' {
		sigRunes[0] = 'b'
	} else {
		sigRunes[0] = 'a'
	}
	env.Signature = string(sigRunes)

	verifier := NewVerifier(VerificationPolicy{})
	if err := verifier.Verify(payload, env); err != ErrSignatureInvalid {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestQA_AdversarialMalformedHexStrings(t *testing.T) {
	verifier := NewVerifier(VerificationPolicy{})
	payload := []byte("data")

	malformedEnvelopes := []*SignedBundleEnvelope{
		nil,
		{PayloadDigest: "sha256:abcd", PublicKey: "invalid_hex_g_z", Signature: "abcd"},
		{PayloadDigest: "sha256:abcd", PublicKey: "1234", Signature: "5678"}, // Too short
		{PayloadDigest: "sha256:abcd", PublicKey: "", Signature: ""},
	}

	for i, env := range malformedEnvelopes {
		err := verifier.Verify(payload, env)
		if err == nil {
			t.Fatalf("case %d expected error on malformed envelope", i)
		}
	}
}
