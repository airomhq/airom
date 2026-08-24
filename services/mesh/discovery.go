package mesh

import (
	"fmt"
	"sync"
	"time"
)

// Engine manages cluster discovery and mesh aggregation.
type Engine struct {
	clusters map[string]*ClusterNode
	mu       sync.RWMutex
}

// NewEngine constructs a federated mesh discovery engine.
func NewEngine() *Engine {
	return &Engine{
		clusters: make(map[string]*ClusterNode),
	}
}

// RegisterCluster adds or updates a cluster node in the mesh.
func (e *Engine) RegisterCluster(cluster ClusterNode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clusters[cluster.ID] = &cluster
}

// IngestWorkloads appends discovered AI workloads to a cluster.
func (e *Engine) IngestWorkloads(clusterID string, workloads []AIWorkload) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	c, ok := e.clusters[clusterID]
	if !ok {
		return fmt.Errorf("cluster not found in mesh: %s", clusterID)
	}

	c.Workloads = append(c.Workloads, workloads...)
	return nil
}

// BuildTopology aggregates all clusters into an enterprise mesh view.
func (e *Engine) BuildTopology() MeshTopology {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var topo MeshTopology
	topo.LastSynced = time.Now().UTC()

	for _, c := range e.clusters {
		topo.Clusters = append(topo.Clusters, *c)
		topo.TotalWorkloads += len(c.Workloads)
		for _, w := range c.Workloads {
			topo.TotalGPUs += w.GPUAllocated
		}
	}

	return topo
}
