package mesh

import (
	"testing"
)

func TestMesh_RegisterAndAggregate(t *testing.T) {
	engine := NewEngine()

	// Register AWS, GCP, Azure clusters
	engine.RegisterCluster(ClusterNode{ID: "eks-us-east-1", Provider: ProviderAWS, Region: "us-east-1"})
	engine.RegisterCluster(ClusterNode{ID: "gke-europe-west1", Provider: ProviderGCP, Region: "europe-west1"})
	engine.RegisterCluster(ClusterNode{ID: "aks-eastus2", Provider: ProviderAzure, Region: "eastus2"})

	// Ingest workloads
	err := engine.IngestWorkloads("eks-us-east-1", []AIWorkload{
		{ID: "w1", ClusterID: "eks-us-east-1", Type: TypeVLLM, ModelName: "meta-llama/Llama-3-70B", GPUAllocated: 4},
		{ID: "w2", ClusterID: "eks-us-east-1", Type: TypeTGI, ModelName: "mistralai/Mistral-7B", GPUAllocated: 1},
	})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	err = engine.IngestWorkloads("gke-europe-west1", []AIWorkload{
		{ID: "w3", ClusterID: "gke-europe-west1", Type: TypeTriton, ModelName: "bge-large-en-v1.5", GPUAllocated: 2},
	})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	topo := engine.BuildTopology()
	if len(topo.Clusters) != 3 {
		t.Errorf("expected 3 clusters, got %d", len(topo.Clusters))
	}
	if topo.TotalWorkloads != 3 {
		t.Errorf("expected 3 workloads, got %d", topo.TotalWorkloads)
	}
	if topo.TotalGPUs != 7 {
		t.Errorf("expected 7 total GPUs, got %d", topo.TotalGPUs)
	}
}
