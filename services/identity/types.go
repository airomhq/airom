// Package identity implements SPIFFE/SPIRE workload attestation and agent identity verification
// for autonomous AI agents and microservices (ARCHITECTURE.md §16).
package identity

import (
	"time"
)

// SVIDType classifies the cryptographic credential format.
type SVIDType string

const (
	SVIDTypeX509 SVIDType = "x509_svid"
	SVIDTypeJWT  SVIDType = "jwt_svid"
)

// AgentIdentity represents an attested autonomous AI agent in the enterprise.
type AgentIdentity struct {
	SPIFFEID    string            `json:"spiffeId"` // spiffe://domain/ns/default/agent/rag-worker-1
	TrustDomain string            `json:"trustDomain"`
	Namespace   string            `json:"namespace"`
	AgentName   string            `json:"agentName"`
	ModelBound  string            `json:"modelBound"`
	Scopes      []string          `json:"scopes"` // "read:aibom", "invoke:gateway"
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// SVIDCredential contains the issued token and validity lifespan.
type SVIDCredential struct {
	SPIFFEID  string    `json:"spiffeId"`
	Type      SVIDType  `json:"type"`
	Token     string    `json:"token"` // Cryptographic signature / JWT
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
