package signature

import (
	"testing"
	"time"
)

func TestSignature_SignAndVerify(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	payload := []byte("rule_pack_data_stream_content")
	signerID := "compliance@enterprise.com"
	issuer := "https://accounts.google.com"

	env, err := SignRuleBundle(payload, keyPair, signerID, issuer, 1*time.Hour)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	verifier := NewVerifier(VerificationPolicy{
		AllowedSigners:   []string{signerID},
		RequireNotExpire: true,
	})

	if err := verifier.Verify(payload, env); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestSignature_TamperedPayloadRejection(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	payload := []byte("legitimate_rule_content")

	env, err := SignRuleBundle(payload, keyPair, "signer@test.com", "issuer", 1*time.Hour)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	verifier := NewVerifier(VerificationPolicy{})

	tamperedPayload := []byte("tampered_rule_content")
	if err := verifier.Verify(tamperedPayload, env); err == nil {
		t.Fatalf("expected verification failure on tampered payload, got nil")
	}
}

func TestSignature_PolicyEnforcement(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	payload := []byte("policy_test")

	// Expired signature
	env, _ := SignRuleBundle(payload, keyPair, "untrusted@attacker.com", "issuer", -10*time.Minute)

	// Policy requires trusted signer and non-expired signature
	verifier := NewVerifier(VerificationPolicy{
		AllowedSigners:   []string{"trusted@company.com"},
		RequireNotExpire: true,
	})

	if err := verifier.Verify(payload, env); err != ErrExpiredSignature {
		t.Errorf("expected ErrExpiredSignature, got %v", err)
	}
}
