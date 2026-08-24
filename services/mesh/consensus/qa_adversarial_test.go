package consensus

import (
	"testing"
)

func TestQA_AdversarialForgedPrevHash(t *testing.T) {
	ledger := NewLedger()
	_, _ = ledger.AppendBlock("c1", "s", []string{"ev1"})

	// Manually tamper with block 1's prev hash
	ledger.chain[1].Header.PrevHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	err := ledger.ValidateChain()
	if err == nil {
		t.Fatalf("expected chain validation error on forged prevHash")
	}
}

func TestQA_AdversarialForgedMerkleRoot(t *testing.T) {
	ledger := NewLedger()
	_, _ = ledger.AppendBlock("c1", "s", []string{"ORIGINAL_EVENT"})

	// Tamper with events without updating block hash or merkle root
	ledger.chain[1].Events[0] = "FORGED_MALICIOUS_EVENT"

	err := ledger.ValidateChain()
	if err == nil {
		t.Fatalf("expected chain validation error on event payload tampering")
	}
}
