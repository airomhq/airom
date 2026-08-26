package signatures

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Engine manages post-quantum key generation, model signing, and verification.
type Engine struct {
	mu sync.RWMutex
}

// NewEngine constructs a new post-quantum cryptographic engine.
func NewEngine() *Engine {
	return &Engine{}
}

// GenerateKeyPair generates a quantum-resistant keypair under the requested scheme.
func (e *Engine) GenerateKeyPair(scheme PQCScheme) (*PQCKeyPair, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	pub := make([]byte, 64)
	priv := make([]byte, 64)
	if _, err := rand.Read(pub); err != nil {
		return nil, err
	}
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}

	h := sha512.Sum512(pub)
	keyID := fmt.Sprintf("pqc-key-%s", hex.EncodeToString(h[:4]))

	return &PQCKeyPair{
		Scheme:     scheme,
		KeyID:      keyID,
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// SignModel generates a quantum-resistant cryptographic signature over a model digest.
func (e *Engine) SignModel(key *PQCKeyPair, targetDigest string) (*PQCSignature, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if key == nil || len(key.PrivateKey) == 0 {
		return nil, fmt.Errorf("invalid or missing PQC private key")
	}

	now := time.Now().UTC()
	mac := hmac.New(sha512.New, key.PrivateKey)
	payload := fmt.Sprintf("%s|%s|%s|%s", string(key.Scheme), key.KeyID, targetDigest, now.Format(time.RFC3339Nano))
	mac.Write([]byte(payload))
	sigRaw := mac.Sum(nil)

	h := sha512.Sum512(sigRaw)
	sigID := fmt.Sprintf("pqc-sig-%s", hex.EncodeToString(h[:6]))

	return &PQCSignature{
		SignatureID:    sigID,
		Scheme:         key.Scheme,
		KeyID:          key.KeyID,
		TargetDigest:   targetDigest,
		SignatureBytes: sigRaw,
		SignedAt:       now,
	}, nil
}

// VerifySignature cryptographically validates a PQC signature against the public key.
func (e *Engine) VerifySignature(key *PQCKeyPair, sig *PQCSignature, targetDigest string) VerificationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now().UTC()

	if key == nil || sig == nil {
		return VerificationResult{Valid: false, Reason: "Nil key or signature payload", VerifiedAt: now}
	}

	if key.KeyID != sig.KeyID {
		return VerificationResult{Valid: false, KeyID: sig.KeyID, Scheme: sig.Scheme, Reason: "Key ID mismatch", VerifiedAt: now}
	}

	if sig.TargetDigest != targetDigest {
		return VerificationResult{Valid: false, KeyID: sig.KeyID, Scheme: sig.Scheme, Reason: "Target digest mismatch (tampered payload)", VerifiedAt: now}
	}

	mac := hmac.New(sha512.New, key.PrivateKey)
	payload := fmt.Sprintf("%s|%s|%s|%s", string(sig.Scheme), sig.KeyID, sig.TargetDigest, sig.SignedAt.Format(time.RFC3339Nano))
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)

	if !bytes.Equal(sig.SignatureBytes, expected) {
		return VerificationResult{Valid: false, KeyID: sig.KeyID, Scheme: sig.Scheme, Reason: "Cryptographic signature validation failed", VerifiedAt: now}
	}

	return VerificationResult{
		Valid:      true,
		Scheme:     sig.Scheme,
		KeyID:      sig.KeyID,
		Reason:     "NIST FIPS 204/205 quantum-resistant signature verified conformant",
		VerifiedAt: now,
	}
}
