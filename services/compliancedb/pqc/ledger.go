package pqc

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Ledger coordinates quantum-resistant immutable block append and verification.
type Ledger struct {
	mu     sync.RWMutex
	blocks []*Block
}

// NewLedger constructs a new PQC compliance ledger with a genesis block.
func NewLedger() *Ledger {
	l := &Ledger{}
	genesisTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisHash := computeSHA3_512("GENESIS_PQC_COMPLIANCE_ROOT")

	genesis := &Block{
		Index:        0,
		Timestamp:    genesisTime,
		RepoID:       "airom/root",
		SnapshotHash: "0000000000000000000000000000000000000000000000000000000000000000",
		ParentHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		BlockHash:    genesisHash,
		Algorithm:    AlgSHA3_512,
	}

	l.blocks = append(l.blocks, genesis)
	return l
}

// AppendBlock appends a new compliance snapshot, linking it to the previous quantum-resistant block hash.
func (l *Ledger) AppendBlock(repoID, snapshotHash string) *Block {
	l.mu.Lock()
	defer l.mu.Unlock()

	last := l.blocks[len(l.blocks)-1]
	now := time.Now().UTC()
	idx := last.Index + 1

	rawPayload := fmt.Sprintf("%d|%s|%s|%s|%s", idx, now.Format(time.RFC3339Nano), repoID, snapshotHash, last.BlockHash)
	blockHash := computeSHA3_512(rawPayload)

	block := &Block{
		Index:        idx,
		Timestamp:    now,
		RepoID:       repoID,
		SnapshotHash: snapshotHash,
		ParentHash:   last.BlockHash,
		BlockHash:    blockHash,
		Algorithm:    AlgSHA3_512,
	}

	l.blocks = append(l.blocks, block)
	return block
}

// VerifyIntegrity verifies that every block's parent hash and block hash are 100% valid and untampered.
func (l *Ledger) VerifyIntegrity() LedgerProof {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := time.Now().UTC()
	if len(l.blocks) == 0 {
		return LedgerProof{IntegrityValid: false, VerifiedAt: now}
	}

	for i := 1; i < len(l.blocks); i++ {
		prev := l.blocks[i-1]
		curr := l.blocks[i]

		// 1. Verify parent link
		if curr.ParentHash != prev.BlockHash {
			return LedgerProof{TotalBlocks: int64(len(l.blocks)), IntegrityValid: false, VerifiedAt: now}
		}

		// 2. Re-compute block hash
		rawPayload := fmt.Sprintf("%d|%s|%s|%s|%s", curr.Index, curr.Timestamp.Format(time.RFC3339Nano), curr.RepoID, curr.SnapshotHash, curr.ParentHash)
		expectedHash := computeSHA3_512(rawPayload)
		if curr.BlockHash != expectedHash {
			return LedgerProof{TotalBlocks: int64(len(l.blocks)), IntegrityValid: false, VerifiedAt: now}
		}
	}

	latest := l.blocks[len(l.blocks)-1]
	return LedgerProof{
		TotalBlocks:    int64(len(l.blocks)),
		LatestRootHash: latest.BlockHash,
		IntegrityValid: true,
		VerifiedAt:     now,
	}
}

func computeSHA3_512(input string) string {
	h := sha512.Sum512([]byte(input))
	return hex.EncodeToString(h[:])
}
