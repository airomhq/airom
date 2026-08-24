package signature

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Verifier enforces cryptographic provenance and policy on rule bundles.
type Verifier struct {
	policy VerificationPolicy
}

// NewVerifier constructs a verifier with an explicit verification policy.
func NewVerifier(policy VerificationPolicy) *Verifier {
	return &Verifier{policy: policy}
}

// Verify verifies that the envelope cryptographically signs payloadBytes and satisfies policy.
func (v *Verifier) Verify(payloadBytes []byte, env *SignedBundleEnvelope) error {
	if env == nil {
		return fmt.Errorf("nil envelope")
	}

	// 1. Verify payload hash match
	actualHash := sha256.Sum256(payloadBytes)
	actualDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(actualHash[:]))
	if actualDigest != env.PayloadDigest {
		return fmt.Errorf("payload digest mismatch: expected %s, got %s", env.PayloadDigest, actualDigest)
	}

	// 2. Check expiration if policy requires
	if v.policy.RequireNotExpire && !env.ExpiresAt.IsZero() {
		if time.Now().UTC().After(env.ExpiresAt) {
			return ErrExpiredSignature
		}
	}

	// 3. Verify Signer Identity Policy
	if len(v.policy.AllowedSigners) > 0 {
		matchedSigner := false
		for _, s := range v.policy.AllowedSigners {
			if s == env.SignerID {
				matchedSigner = true
				break
			}
		}
		if !matchedSigner {
			return ErrUntrustedIdentity
		}
	}

	// 4. Decode public key and signature
	pubBytes, err := hex.DecodeString(env.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key format: %w", err)
	}

	sigBytes, err := hex.DecodeString(env.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// 5. Verify cryptographic signature
	messageSigned := fmt.Sprintf("%s:%s:%s:%d", env.PayloadDigest, env.SignerID, env.Issuer, env.SignedAt.Unix())
	if !ed25519.Verify(pubBytes, []byte(messageSigned), sigBytes) {
		return ErrSignatureInvalid
	}

	return nil
}
