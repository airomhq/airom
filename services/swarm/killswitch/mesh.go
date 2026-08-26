package killswitch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Mesh coordinates distributed kill switches and immediate execution halts.
type Mesh struct {
	mu           sync.RWMutex
	globalHalt   bool
	globalReason HaltReason
	haltedNodes  map[string]HaltReason // agentID -> reason
	haltedClusts map[string]HaltReason // clusterID -> reason
	nodes        map[string]*NodeStatus
}

// NewMesh constructs a new distributed kill-switch mesh.
func NewMesh() *Mesh {
	return &Mesh{
		haltedNodes:  make(map[string]HaltReason),
		haltedClusts: make(map[string]HaltReason),
		nodes:        make(map[string]*NodeStatus),
	}
}

// RegisterAgent registers an active agent node into the mesh.
func (m *Mesh) RegisterAgent(agentID, clusterID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[agentID] = &NodeStatus{
		AgentID:     agentID,
		ClusterID:   clusterID,
		IsHalted:    false,
		LastCheckIn: time.Now().UTC(),
	}
}

// BroadcastKillSignal propagates a kill signal across single agents, clusters, or global mesh.
func (m *Mesh) BroadcastKillSignal(sig KillSignal) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", sig.Scope, sig.TargetID, sig.Reason, now.Format(time.RFC3339Nano))))
	sigID := fmt.Sprintf("kill-%s", hex.EncodeToString(h[:4]))

	switch sig.Scope {
	case ScopeGlobalMesh:
		m.globalHalt = true
		m.globalReason = sig.Reason
		for _, n := range m.nodes {
			n.IsHalted = true
			n.HaltReason = sig.Reason
		}
	case ScopeAgentCluster:
		m.haltedClusts[sig.TargetID] = sig.Reason
		for _, n := range m.nodes {
			if n.ClusterID == sig.TargetID {
				n.IsHalted = true
				n.HaltReason = sig.Reason
			}
		}
	case ScopeSingleAgent:
		m.haltedNodes[sig.TargetID] = sig.Reason
		if n, ok := m.nodes[sig.TargetID]; ok {
			n.IsHalted = true
			n.HaltReason = sig.Reason
		}
	}

	return sigID
}

// CanExecute returns true if the agent is authorized to proceed (not halted).
func (m *Mesh) CanExecute(agentID string) (bool, HaltReason) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.globalHalt {
		return false, m.globalReason
	}

	if reason, ok := m.haltedNodes[agentID]; ok {
		return false, reason
	}

	if node, ok := m.nodes[agentID]; ok {
		if reason, ok := m.haltedClusts[node.ClusterID]; ok {
			return false, reason
		}
	}

	return true, ""
}
