package mesh

import (
	"testing"
)

func TestQA_AdversarialNonExistentClusterIngestion(t *testing.T) {
	engine := NewEngine()

	err := engine.IngestWorkloads("non-existent-cluster", []AIWorkload{{ID: "w1"}})
	if err == nil {
		t.Fatalf("expected error ingesting into non-existent cluster")
	}
}

func TestQA_AdversarialEmptyMeshTopology(t *testing.T) {
	engine := NewEngine()

	topo := engine.BuildTopology()
	if len(topo.Clusters) != 0 || topo.TotalWorkloads != 0 || topo.TotalGPUs != 0 {
		t.Errorf("expected clean empty topology, got %+v", topo)
	}
}
