package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// NodeRole represents whether a node is the active cluster leader or replica follower.
type NodeRole string

const (
	RoleLeader    NodeRole = "LEADER"
	RoleFollower  NodeRole = "FOLLOWER"
	RoleCandidate NodeRole = "CANDIDATE"
)

// NodeStatus indicates operational health of an AIROM cluster instance.
type NodeStatus string

const (
	NodeStatusHealthy  NodeStatus = "HEALTHY"
	NodeStatusDraining NodeStatus = "DRAINING"
	NodeStatusDegraded NodeStatus = "DEGRADED"
	NodeStatusDead     NodeStatus = "DEAD"
)

// QuorumStatus captures overall high-availability consensus health.
type QuorumStatus string

const (
	QuorumHealthy        QuorumStatus = "HEALTHY"
	QuorumDegraded       QuorumStatus = "DEGRADED"
	QuorumSplitBrainRisk QuorumStatus = "SPLIT_BRAIN_RISK"
	QuorumLost           QuorumStatus = "NO_QUORUM"
)

// ClusterNode represents a single runtime server in the high-availability cluster.
type ClusterNode struct {
	NodeID          string     `json:"node_id"`
	Hostname        string     `json:"hostname"`
	Port            int        `json:"port"`
	Role            NodeRole   `json:"role"`
	Status          NodeStatus `json:"status"`
	Term            int64      `json:"term"`
	LastHeartbeatAt time.Time  `json:"last_heartbeat_at"`
	ServicesActive  []string   `json:"services_active"`
}

// ClusterState represents the complete global consensus state of the AIROM HA deployment.
type ClusterState struct {
	ClusterID      string        `json:"cluster_id"`
	ActiveLeaderID string        `json:"active_leader_id"`
	Term           int64         `json:"term"`
	Quorum         QuorumStatus  `json:"quorum"`
	TotalNodes     int           `json:"total_nodes"`
	HealthyNodes   int           `json:"healthy_nodes"`
	Nodes          []ClusterNode `json:"nodes"`
	EvaluatedAt    time.Time     `json:"evaluated_at"`
	StateChecksum  string        `json:"state_checksum"`
}

// ComputeStateChecksum generates a deterministic SHA-256 fingerprint for the cluster state.
func (s *ClusterState) ComputeStateChecksum() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%d|%s|%d|%d|%s\n",
		s.ClusterID, s.ActiveLeaderID, s.Term, s.Quorum,
		s.TotalNodes, s.HealthyNodes, s.EvaluatedAt.UTC().Format(time.RFC3339))
	for _, n := range s.Nodes {
		_, _ = fmt.Fprintf(h, "%s:%s:%s:%d\n", n.NodeID, n.Role, n.Status, n.Term)
	}
	s.StateChecksum = hex.EncodeToString(h.Sum(nil))
	return s.StateChecksum
}
