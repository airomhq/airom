package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ClusterManager coordinates node heartbeats, leader elections, and high-availability cluster consensus.
type ClusterManager struct {
	mu           sync.RWMutex
	clusterID    string
	term         int64
	leaderID     string
	nodes        map[string]*ClusterNode
	heartbeatTTL time.Duration
}

// NewClusterManager constructs a new ClusterManager instance.
func NewClusterManager(clusterID string) *ClusterManager {
	if clusterID == "" {
		clusterID = fmt.Sprintf("cluster_%s", randHex(4))
	}
	return &ClusterManager{
		clusterID:    clusterID,
		term:         1,
		nodes:        make(map[string]*ClusterNode),
		heartbeatTTL: 15 * time.Second,
	}
}

// RegisterNode adds or updates a node in the cluster inventory.
func (m *ClusterManager) RegisterNode(node ClusterNode) error {
	if node.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	node.LastHeartbeatAt = now
	node.Status = NodeStatusHealthy

	if m.leaderID == "" {
		node.Role = RoleLeader
		node.Term = m.term
		m.leaderID = node.NodeID
	} else if node.NodeID == m.leaderID {
		node.Role = RoleLeader
		node.Term = m.term
	} else {
		node.Role = RoleFollower
		node.Term = m.term
	}

	m.nodes[node.NodeID] = &node
	return nil
}

// RecordHeartbeat refreshes node liveness and active services.
func (m *ClusterManager) RecordHeartbeat(nodeID string, servicesActive []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, ok := m.nodes[nodeID]
	if !ok {
		return fmt.Errorf("node not registered: %s", nodeID)
	}

	node.LastHeartbeatAt = time.Now().UTC()
	node.Status = NodeStatusHealthy
	if len(servicesActive) > 0 {
		node.ServicesActive = servicesActive
	}
	return nil
}

// ElectLeader triggers a new election round if the active leader is degraded or unassigned.
func (m *ClusterManager) ElectLeader() (*ClusterNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.term++
	var candidates []*ClusterNode

	now := time.Now().UTC()
	for _, n := range m.nodes {
		if now.Sub(n.LastHeartbeatAt) <= m.heartbeatTTL && n.Status == NodeStatusHealthy {
			candidates = append(candidates, n)
		} else {
			n.Status = NodeStatusDead
			n.Role = RoleFollower
		}
	}

	if len(candidates) == 0 {
		m.leaderID = ""
		return nil, fmt.Errorf("no healthy candidate nodes available for leader election")
	}

	// Deterministic selection (sort by NodeID)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].NodeID < candidates[j].NodeID
	})

	newLeader := candidates[0]
	m.leaderID = newLeader.NodeID

	for _, n := range m.nodes {
		if n.NodeID == m.leaderID {
			n.Role = RoleLeader
			n.Term = m.term
		} else {
			n.Role = RoleFollower
			n.Term = m.term
		}
	}

	return newLeader, nil
}

// GetClusterState retrieves the global cluster health and quorum status.
func (m *ClusterManager) GetClusterState() *ClusterState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now().UTC()
	totalNodes := len(m.nodes)
	healthyNodes := 0
	nodesList := make([]ClusterNode, 0, totalNodes)

	for _, n := range m.nodes {
		nodeCopy := *n
		if now.Sub(n.LastHeartbeatAt) > m.heartbeatTTL {
			nodeCopy.Status = NodeStatusDead
		} else {
			healthyNodes++
		}
		nodesList = append(nodesList, nodeCopy)
	}

	sort.Slice(nodesList, func(i, j int) bool {
		return nodesList[i].NodeID < nodesList[j].NodeID
	})

	var quorum QuorumStatus
	majority := (totalNodes / 2) + 1
	switch {
	case healthyNodes >= majority && healthyNodes == totalNodes:
		quorum = QuorumHealthy
	case healthyNodes >= majority:
		quorum = QuorumDegraded
	case healthyNodes > 0:
		quorum = QuorumSplitBrainRisk
	default:
		quorum = QuorumLost
	}

	state := &ClusterState{
		ClusterID:      m.clusterID,
		ActiveLeaderID: m.leaderID,
		Term:           m.term,
		Quorum:         quorum,
		TotalNodes:     totalNodes,
		HealthyNodes:   healthyNodes,
		Nodes:          nodesList,
		EvaluatedAt:    now,
	}

	state.ComputeStateChecksum()
	return state
}

// RenderClusterDashboard formats an ASCII terminal view of the high-availability cluster topology.
func RenderClusterDashboard(s *ClusterState) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "  AIROM HIGH-AVAILABILITY CLUSTER TOPOLOGY & CONSENSUS DASHBOARD\n")
	fmt.Fprintf(&sb, "  Cluster ID: %s | Term: %d | Active Leader: %s | Quorum Status: [%s]\n",
		s.ClusterID, s.Term, s.ActiveLeaderID, s.Quorum)
	fmt.Fprintf(&sb, "  Total Nodes: %d | Healthy: %d | Evaluated: %s\n",
		s.TotalNodes, s.HealthyNodes, s.EvaluatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&sb, "====================================================================================================\n\n")

	fmt.Fprintf(&sb, "%-18s | %-16s | %-10s | %-10s | %-6s | %-28s\n",
		"NODE ID", "HOSTNAME", "ROLE", "STATUS", "TERM", "ACTIVE SERVICES")
	fmt.Fprintf(&sb, "-------------------+------------------+------------+------------+--------+-----------------------------\n")

	for _, n := range s.Nodes {
		services := strings.Join(n.ServicesActive, ", ")
		if len(services) > 28 {
			services = services[:25] + "..."
		}
		if services == "" {
			services = "all-core-services"
		}

		roleStr := string(n.Role)
		if n.Role == RoleLeader {
			roleStr = "👑 " + roleStr
		}

		fmt.Fprintf(&sb, "%-18s | %-16s | %-10s | %-10s | %-6d | %-28s\n",
			n.NodeID, n.Hostname, roleStr, n.Status, n.Term, services)
	}

	fmt.Fprintf(&sb, "\n====================================================================================================\n")
	return sb.String()
}
