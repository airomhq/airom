package grid

import (
	"context"
	"fmt"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

func TestGrid_PartitionPlanningAndAggregation(t *testing.T) {
	coord := NewCoordinator()

	// Register 3 worker nodes
	for i := 0; i < 3; i++ {
		coord.RegisterWorker(&WorkerNode{
			ID:       fmt.Sprintf("node-%d", i),
			Role:     RoleScanner,
			Capacity: 10,
		})
	}

	// 1,500 file paths
	allFiles := make([]string, 1500)
	for i := 0; i < 1500; i++ {
		allFiles[i] = fmt.Sprintf("src/pkg_%d/file.py", i)
	}

	spec := GridScanSpec{
		JobID:     "job-100",
		OrgID:     "org-enterprise",
		ShardSize: 500,
	}

	partitions := coord.PlanPartitions(spec, allFiles)
	if len(partitions) != 3 {
		t.Fatalf("expected 3 partitions, got %d", len(partitions))
	}

	// Workers execute and submit partial results
	for i, part := range partitions {
		partInv := &airom.Inventory{
			Components: []airom.Component{
				{
					ID:       airom.ID(fmt.Sprintf("airom:comp_part_%d", i)),
					Kind:     airom.KindHostedLLM,
					Name:     fmt.Sprintf("model-shard-%d", i),
					Provider: airom.KnownString("openai"),
				},
				{
					ID:       "airom:shared_langchain",
					Kind:     airom.KindFramework,
					Name:     "langchain",
					Provider: airom.KnownString("langchain-ai"),
					Evidence: airom.Evidence{
						Occurrences: []airom.Occurrence{
							{Location: airom.Location{Path: fmt.Sprintf("src/pkg_%d/file.py", i*500)}},
						},
					},
				},
			},
			Relationships: []airom.Relationship{
				{
					From: "airom:shared_langchain",
					To:   airom.ID(fmt.Sprintf("airom:comp_part_%d", i)),
					Type: airom.RelDependsOn,
				},
			},
		}

		if err := coord.SubmitPartitionResult(spec.JobID, part.PartitionID, partInv); err != nil {
			t.Fatalf("submit partition %d failed: %v", i, err)
		}
	}

	masterInv, err := coord.AggregateMasterInventory(context.Background(), spec.JobID)
	if err != nil {
		t.Fatalf("aggregation failed: %v", err)
	}

	// Expected: 3 shard models + 1 deduplicated langchain = 4 components
	if len(masterInv.Components) != 4 {
		t.Errorf("expected 4 deduplicated components, got %d", len(masterInv.Components))
	}

	// Check shared langchain occurrences merged (3 occurrences)
	foundShared := false
	for _, comp := range masterInv.Components {
		if comp.ID == "airom:shared_langchain" {
			foundShared = true
			if len(comp.Evidence.Occurrences) != 3 {
				t.Errorf("expected 3 merged occurrences for shared component, got %d", len(comp.Evidence.Occurrences))
			}
		}
	}
	if !foundShared {
		t.Errorf("shared component missing in master inventory")
	}

	// Expected: 3 relationships
	if len(masterInv.Relationships) != 3 {
		t.Errorf("expected 3 relationships, got %d", len(masterInv.Relationships))
	}
}
