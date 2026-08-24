// Package signature implements Cosign/Sigstore and TUF cryptographic signing and verification
// for OCI-distributed AI compliance rule bundles (ARCHITECTURE.md §10, §16).
package signature

import (
	"errors"
	"time"
)

var (
	// ErrSignatureInvalid is returned when cryptographic signature verification fails.
	ErrSignatureInvalid = errors.New("signature: verification failed")
	// ErrKeyMismatch is returned when the public key does not match the signature.
	ErrKeyMismatch = errors.New("signature: public key mismatch")
	// ErrExpiredSignature is returned when a signature validity window has expired.
	ErrExpiredSignature = errors.New("signature: signature has expired")
	// ErrUntrustedIdentity is returned when signer SAN or issuer is not in policy.
	ErrUntrustedIdentity = errors.New("signature: signer identity is not trusted by policy")
)

// SignedBundleEnvelope wraps an OCI artifact manifest and payload with cryptographic signatures.
type SignedBundleEnvelope struct {
	PayloadDigest string            `json:"payloadDigest"` // SHA-256
	SignerID      string            `json:"signerId"`      // email or SPIFFE ID
	Issuer        string            `json:"issuer"`        // e.g. https://accounts.google.com, https://github.com/login/oauth
	SignedAt      time.Time         `json:"signedAt"`
	ExpiresAt     time.Time         `json:"expiresAt,omitempty"`
	Signature     string            `json:"signature"` // hex or base64
	PublicKey     string            `json:"publicKey"` // hex or PEM
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// VerificationPolicy specifies the trust requirements for rule bundle ingestion.
type VerificationPolicy struct {
	AllowedSigners   []string `json:"allowedSigners,omitempty"`
	AllowedIssuers   []string `json:"allowedIssuers,omitempty"`
	TrustedKeyPEMs   []string `json:"trustedKeyPEMs,omitempty"`
	RequireNotExpire bool     `json:"requireNotExpire"`
}
