package pqc

import (
	"testing"
)

func TestQA_AdversarialForgedParentHash(t *testing.T) {
	ledger := NewLedger()

	_ = ledger.AppendBlock("repo-1", "hash-1")
	_ = ledger.AppendBlock("repo-2", "hash-2")

	// Forged parent hash
	ledger.blocks[2].ParentHash = "0000000000000000000000000000000000000000000000000000000000000000"

	proof := ledger.VerifyIntegrity()
	if proof.IntegrityValid {
		t.Fatalf("SECURITY VIOLATION: ledger accepted forged parent hash")
	}
}

func TestQA_AdversarialEmptyRepoAndSnapshot(t *testing.T) {
	ledger := NewLedger()
	b := ledger.AppendBlock("", "")
	if b == nil || b.BlockHash == "" {
		t.Fatalf("expected valid block produced on empty fields")
	}

	proof := ledger.VerifyIntegrity()
	if !proof.IntegrityValid {
		t.Fatalf("expected valid integrity on empty string block")
	}
}
