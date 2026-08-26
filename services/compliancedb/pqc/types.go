// Package pqc provides quantum-resistant immutable ledger chaining and Merkle proofs for ComplianceDB.
package pqc

import (
	"time"
)

// HashAlg defines the quantum-resistant hash algorithm.
type HashAlg string

const (
	AlgSHA3_512 HashAlg = "SHA3-512"
	AlgSHAKE256 HashAlg = "SHAKE-256"
)

// Block represents an immutable quantum-resistant compliance ledger entry.
type Block struct {
	Index        int64     `json:"index"`
	Timestamp    time.Time `json:"timestamp"`
	RepoID       string    `json:"repoId"`
	SnapshotHash string    `json:"snapshotHash"` // Digest of compliance state
	ParentHash   string    `json:"parentHash"`   // Quantum-resistant parent hash
	BlockHash    string    `json:"blockHash"`    // SHA3-512 of current block content
	Algorithm    HashAlg   `json:"algorithm"`
}

// LedgerProof contains the cryptographic proof of unbroken chain integrity.
type LedgerProof struct {
	TotalBlocks    int64     `json:"totalBlocks"`
	LatestRootHash string    `json:"latestRootHash"`
	IntegrityValid bool      `json:"integrityValid"`
	VerifiedAt     time.Time `json:"verifiedAt"`
}
