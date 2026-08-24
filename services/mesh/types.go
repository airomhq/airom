// Package mesh implements multi-cloud federated compliance mesh discovery across Kubernetes clusters
// (ARCHITECTURE.md §7, §16).
package mesh

import (
	"time"
)

// CloudProvider identifies the infrastructure provider.
type CloudProvider string

const (
	ProviderAWS    CloudProvider = "aws"
	ProviderGCP    CloudProvider = "gcp"
	ProviderAzure  CloudProvider = "azure"
	ProviderOnPrem CloudProvider = "on_prem"
)

// WorkloadType classifies the AI serving runtime deployed in a cluster.
type WorkloadType string

const (
	TypeVLLM       WorkloadType = "vllm"
	TypeTGI        WorkloadType = "text_generation_inference"
	TypeTriton     WorkloadType = "triton_inference_server"
	TypeOllama     WorkloadType = "ollama"
	TypeRayCluster WorkloadType = "ray_cluster"
)

// AIWorkload represents an active AI inference workload running in a pod.
type AIWorkload struct {
	ID           string       `json:"id"`
	ClusterID    string       `json:"clusterId"`
	Namespace    string       `json:"namespace"`
	PodName      string       `json:"podName"`
	Type         WorkloadType `json:"type"`
	ModelName    string       `json:"modelName"`
	ImageDigest  string       `json:"imageDigest"`
	GPUAllocated int          `json:"gpuAllocated"`
	DiscoveredAt time.Time    `json:"discoveredAt"`
}

// ClusterNode represents a discovered Kubernetes cluster in the mesh.
type ClusterNode struct {
	ID        string        `json:"id"`
	Provider  CloudProvider `json:"provider"`
	Region    string        `json:"region"`
	Workloads []AIWorkload  `json:"workloads"`
	Status    string        `json:"status"` // healthy | unreachable
}

// MeshTopology represents the entire federated multi-cloud graph.
type MeshTopology struct {
	Clusters       []ClusterNode `json:"clusters"`
	TotalWorkloads int           `json:"totalWorkloads"`
	TotalGPUs      int           `json:"totalGpus"`
	LastSynced     time.Time     `json:"lastSynced"`
}
