// Package signatures implements NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
// post-quantum cryptographic model checkpoint signing and verification.
package signatures

import (
	"time"
)

// PQCScheme enumerates standard NIST post-quantum signature schemes.
type PQCScheme string

const (
	SchemeMLDSA44   PQCScheme = "ML-DSA-44"   // NIST Security Category 2 (Dilithium2)
	SchemeMLDSA65   PQCScheme = "ML-DSA-65"   // NIST Security Category 3 (Dilithium3)
	SchemeMLDSA87   PQCScheme = "ML-DSA-87"   // NIST Security Category 5 (Dilithium5)
	SchemeSLHDSA128 PQCScheme = "SLH-DSA-128" // Stateless Hash-Based (SPHINCS+)
)

// PQCKeyPair represents a quantum-resistant public and private key pair.
type PQCKeyPair struct {
	Scheme     PQCScheme `json:"scheme"`
	KeyID      string    `json:"keyId"`
	PublicKey  []byte    `json:"publicKey"`
	PrivateKey []byte    `json:"privateKey"`
	CreatedAt  time.Time `json:"createdAt"`
}

// PQCSignature represents a quantum-resistant cryptographic attestation for an AI asset.
type PQCSignature struct {
	SignatureID    string    `json:"signatureId"`
	Scheme         PQCScheme `json:"scheme"`
	KeyID          string    `json:"keyId"`
	TargetDigest   string    `json:"targetDigest"` // SHA3-512 / SHAKE-256 digest of model weights
	SignatureBytes []byte    `json:"signatureBytes"`
	SignedAt       time.Time `json:"signedAt"`
}

// VerificationResult contains the verification outcome for a PQC signed model.
type VerificationResult struct {
	Valid      bool      `json:"valid"`
	Scheme     PQCScheme `json:"scheme"`
	KeyID      string    `json:"keyId"`
	Reason     string    `json:"reason"`
	VerifiedAt time.Time `json:"verifiedAt"`
}
