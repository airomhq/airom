// Package consensus implements replicated compliance ledger synchronization across multi-cloud clusters
// (ARCHITECTURE.md §16).
package consensus

import (
	"time"
)

// BlockHeader contains block metadata and cryptographic integrity links.
type BlockHeader struct {
	Index      int64     `json:"index"`
	Timestamp  time.Time `json:"timestamp"`
	PrevHash   string    `json:"prevHash"`
	MerkleRoot string    `json:"merkleRoot"`
	ClusterID  string    `json:"clusterId"`
}

// ComplianceBlock represents an immutable state transition in the federated compliance mesh.
type ComplianceBlock struct {
	Header    BlockHeader `json:"header"`
	BlockHash string      `json:"blockHash"`
	Events    []string    `json:"events"`
	Signer    string      `json:"signer"`
}

// PeerNode represents a participating cluster in consensus validation.
type PeerNode struct {
	ID        string `json:"id"`
	Endpoint  string `json:"endpoint"`
	IsLeader  bool   `json:"isLeader"`
	LastIndex int64  `json:"lastIndex"`
}
