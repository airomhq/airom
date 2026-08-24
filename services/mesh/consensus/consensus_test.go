package consensus

import (
	"fmt"
	"testing"
)

func TestLedger_AppendAndValidate(t *testing.T) {
	ledger := NewLedger()

	clusters := []string{"eks-us-east-1", "gke-europe-west1", "aks-eastus2"}
	for i := 0; i < 9; i++ {
		cID := clusters[i%len(clusters)]
		events := []string{
			fmt.Sprintf("SCAN_COMPLETED:cluster=%s:job=%d", cID, i),
			fmt.Sprintf("COMPLIANCE_STATUS_OK:cluster=%s", cID),
		}
		_, err := ledger.AppendBlock(cID, "operator-node", events)
		if err != nil {
			t.Fatalf("append failed at %d: %v", i, err)
		}
	}

	// 1 genesis + 9 appended = 10 blocks
	if ledger.Length() != 10 {
		t.Fatalf("expected 10 blocks, got %d", ledger.Length())
	}

	if err := ledger.ValidateChain(); err != nil {
		t.Fatalf("chain validation failed: %v", err)
	}
}

func TestLedger_MerkleRootComputation(t *testing.T) {
	events := []string{"ev1", "ev2", "ev3", "ev4"}
	r1 := computeMerkleRoot(events)
	r2 := computeMerkleRoot(events)

	if r1 != r2 || len(r1) != 64 {
		t.Errorf("merkle root mismatch or invalid length: %s", r1)
	}
}
