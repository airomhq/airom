package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Ledger maintains an unbroken cryptographic chain of multi-cloud compliance events.
type Ledger struct {
	chain []ComplianceBlock
	mu    sync.RWMutex
}

// NewLedger initializes a ledger with a genesis block.
func NewLedger() *Ledger {
	genesisHeader := BlockHeader{
		Index:      0,
		Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PrevHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		MerkleRoot: "0000000000000000000000000000000000000000000000000000000000000000",
		ClusterID:  "mesh-genesis",
	}

	genesisHash := computeBlockHash(genesisHeader)
	genesisBlock := ComplianceBlock{
		Header:    genesisHeader,
		BlockHash: genesisHash,
		Events:    []string{"GENESIS_MESH_LEDGER"},
		Signer:    "root-coordinator",
	}

	return &Ledger{
		chain: []ComplianceBlock{genesisBlock},
	}
}

// AppendBlock appends a new compliance event block to the chain.
func (l *Ledger) AppendBlock(clusterID, signer string, events []string) (ComplianceBlock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	lastBlock := l.chain[len(l.chain)-1]
	merkle := computeMerkleRoot(events)

	header := BlockHeader{
		Index:      lastBlock.Header.Index + 1,
		Timestamp:  time.Now().UTC(),
		PrevHash:   lastBlock.BlockHash,
		MerkleRoot: merkle,
		ClusterID:  clusterID,
	}

	blockHash := computeBlockHash(header)
	block := ComplianceBlock{
		Header:    header,
		BlockHash: blockHash,
		Events:    events,
		Signer:    signer,
	}

	l.chain = append(l.chain, block)
	return block, nil
}

// ValidateChain verifies the unbroken cryptographic integrity of all blocks.
func (l *Ledger) ValidateChain() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	for i := 1; i < len(l.chain); i++ {
		curr := l.chain[i]
		prev := l.chain[i-1]

		if curr.Header.PrevHash != prev.BlockHash {
			return fmt.Errorf("chain broken at block %d: prevHash %s != %s", i, curr.Header.PrevHash, prev.BlockHash)
		}

		expectedHash := computeBlockHash(curr.Header)
		if curr.BlockHash != expectedHash {
			return fmt.Errorf("block %d corrupted: hash %s != expected %s", i, curr.BlockHash, expectedHash)
		}

		expectedMerkle := computeMerkleRoot(curr.Events)
		if curr.Header.MerkleRoot != expectedMerkle {
			return fmt.Errorf("block %d merkle root mismatch", i)
		}
	}

	return nil
}

// Length returns the number of blocks in the chain.
func (l *Ledger) Length() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.chain)
}

func computeBlockHash(h BlockHeader) string {
	payload := fmt.Sprintf("%d:%d:%s:%s:%s", h.Index, h.Timestamp.UnixNano(), h.PrevHash, h.MerkleRoot, h.ClusterID)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func computeMerkleRoot(events []string) string {
	if len(events) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}

	var hashes []string
	for _, ev := range events {
		sum := sha256.Sum256([]byte(ev))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}

	for len(hashes) > 1 {
		var next []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				comb := sha256.Sum256([]byte(hashes[i] + hashes[i+1]))
				next = append(next, hex.EncodeToString(comb[:]))
			} else {
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}

	return hashes[0]
}
