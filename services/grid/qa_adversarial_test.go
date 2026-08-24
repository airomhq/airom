package grid

import (
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialUnfinishedPartitions(t *testing.T) {
	coord := NewCoordinator()
	spec := GridScanSpec{JobID: "unf-job", ShardSize: 10}
	files := []string{"f1.py", "f2.py", "f3.py"}

	_ = coord.PlanPartitions(spec, files)

	// Attempt to aggregate before workers have submitted results
	_, err := coord.AggregateMasterInventory(context.Background(), "unf-job")
	if err == nil {
		t.Fatalf("expected error aggregating unfinished job")
	}
}

func TestQA_AdversarialInvalidPartitionSubmissions(t *testing.T) {
	coord := NewCoordinator()

	// Submitting to non-existent job
	err := coord.SubmitPartitionResult("fake-job", 0, &airom.Inventory{})
	if err == nil {
		t.Errorf("expected error submitting to nonexistent job")
	}

	// Submitting to out-of-range partition
	spec := GridScanSpec{JobID: "valid-job", ShardSize: 10}
	_ = coord.PlanPartitions(spec, []string{"f1.py"})

	err = coord.SubmitPartitionResult("valid-job", 99, &airom.Inventory{})
	if err == nil {
		t.Errorf("expected error on out-of-range partition ID 99")
	}
}

func TestQA_AdversarialDuplicatePartitionSubmissions(t *testing.T) {
	coord := NewCoordinator()
	spec := GridScanSpec{JobID: "dup-job", ShardSize: 10}
	_ = coord.PlanPartitions(spec, []string{"f1.py"})

	inv1 := &airom.Inventory{
		Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "v1"}},
	}
	inv2 := &airom.Inventory{
		Components: []airom.Component{{ID: "c1", Kind: airom.KindHostedLLM, Name: "v2"}},
	}

	// First submission
	if err := coord.SubmitPartitionResult("dup-job", 0, inv1); err != nil {
		t.Fatalf("sub 1 failed: %v", err)
	}

	// Duplicate re-submission overrides cleanly
	if err := coord.SubmitPartitionResult("dup-job", 0, inv2); err != nil {
		t.Fatalf("sub 2 failed: %v", err)
	}

	master, err := coord.AggregateMasterInventory(context.Background(), "dup-job")
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}

	if len(master.Components) != 1 || master.Components[0].Name != "v2" {
		t.Errorf("expected updated component from re-submission, got %+v", master.Components)
	}
}
