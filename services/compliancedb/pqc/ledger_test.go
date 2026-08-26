package pqc

import (
	"testing"
)

func TestPQCLedger_AppendAndVerifyIntegrity(t *testing.T) {
	ledger := NewLedger()

	b1 := ledger.AppendBlock("repo-1", "hash-1")
	b2 := ledger.AppendBlock("repo-2", "hash-2")

	if b1.Index != 1 || b2.Index != 2 {
		t.Fatalf("unexpected indices: %d, %d", b1.Index, b2.Index)
	}

	proof := ledger.VerifyIntegrity()
	if !proof.IntegrityValid || proof.TotalBlocks != 3 {
		t.Fatalf("expected valid integrity proof for 3 blocks, got: %+v", proof)
	}
}

func TestPQCLedger_TamperDetection(t *testing.T) {
	ledger := NewLedger()

	_ = ledger.AppendBlock("repo-1", "hash-1")
	_ = ledger.AppendBlock("repo-2", "hash-2")

	// Tamper with block 1 snapshot hash
	ledger.blocks[1].SnapshotHash = "forged_snapshot_hash"

	proof := ledger.VerifyIntegrity()
	if proof.IntegrityValid {
		t.Fatalf("SECURITY VIOLATION: ledger integrity passed on tampered block")
	}
}
