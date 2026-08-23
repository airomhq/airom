package cluster

import (
	"testing"
	"time"
)

func TestQA_AdversarialClusterPartitionAndFailover(t *testing.T) {
	mgr := NewClusterManager("partition-cluster")
	mgr.heartbeatTTL = 50 * time.Millisecond // Fast TTL for testing

	_ = mgr.RegisterNode(ClusterNode{NodeID: "leader-node", Hostname: "node1", Port: 8080})
	_ = mgr.RegisterNode(ClusterNode{NodeID: "backup-node", Hostname: "node2", Port: 8080})

	// Leader is initial leader
	state := mgr.GetClusterState()
	if state.ActiveLeaderID != "leader-node" {
		t.Errorf("expected initial leader leader-node, got %s", state.ActiveLeaderID)
	}

	// Sleep past heartbeat TTL so leader becomes DEAD
	time.Sleep(70 * time.Millisecond)

	// Keep backup node alive
	_ = mgr.RecordHeartbeat("backup-node", nil)

	// Trigger election after leader death
	newLeader, err := mgr.ElectLeader()
	if err != nil {
		t.Fatalf("expected successful failover election, got: %v", err)
	}
	if newLeader.NodeID != "backup-node" {
		t.Errorf("expected backup-node to become new leader, got %s", newLeader.NodeID)
	}
}

func TestQA_AdversarialUnregisteredNodeHeartbeat(t *testing.T) {
	mgr := NewClusterManager("unreg-cluster")

	err := mgr.RecordHeartbeat("unregistered-ghost-node", []string{"service"})
	if err == nil {
		t.Error("expected error when heartbeating unregistered node")
	}
}
