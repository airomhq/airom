package signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// KeyPair holds a generated Ed25519 signing keypair.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new Ed25519 keypair for rule signing.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// SignRuleBundle signs a rule bundle layer digest with an Ed25519 private key.
func SignRuleBundle(payloadBytes []byte, keyPair *KeyPair, signerID, issuer string, validityDuration time.Duration) (*SignedBundleEnvelope, error) {
	if keyPair == nil || len(keyPair.PrivateKey) == 0 {
		return nil, fmt.Errorf("signer: invalid private key")
	}

	payloadHash := sha256.Sum256(payloadBytes)
	payloadDigest := fmt.Sprintf("sha256:%s", hex.EncodeToString(payloadHash[:]))

	now := time.Now().UTC()
	var expiresAt time.Time
	if validityDuration != 0 {
		expiresAt = now.Add(validityDuration)
	}

	// Sign payload hash + signer identity + timestamp
	messageToSign := fmt.Sprintf("%s:%s:%s:%d", payloadDigest, signerID, issuer, now.Unix())
	sig := ed25519.Sign(keyPair.PrivateKey, []byte(messageToSign))

	return &SignedBundleEnvelope{
		PayloadDigest: payloadDigest,
		SignerID:      signerID,
		Issuer:        issuer,
		SignedAt:      now,
		ExpiresAt:     expiresAt,
		Signature:     hex.EncodeToString(sig),
		PublicKey:     hex.EncodeToString(keyPair.PublicKey),
	}, nil
}
