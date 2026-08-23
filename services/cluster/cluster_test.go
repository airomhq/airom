package cluster

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCluster_Register_Heartbeat_Election(t *testing.T) {
	mgr := NewClusterManager("test-cluster-01")

	node1 := ClusterNode{
		NodeID:   "node-1",
		Hostname: "airom-node-1.prod",
		Port:     8080,
	}
	node2 := ClusterNode{
		NodeID:   "node-2",
		Hostname: "airom-node-2.prod",
		Port:     8080,
	}
	node3 := ClusterNode{
		NodeID:   "node-3",
		Hostname: "airom-node-3.prod",
		Port:     8080,
	}

	_ = mgr.RegisterNode(node1)
	_ = mgr.RegisterNode(node2)
	_ = mgr.RegisterNode(node3)

	state := mgr.GetClusterState()
	if state.TotalNodes != 3 {
		t.Errorf("expected 3 nodes, got %d", state.TotalNodes)
	}
	if state.Quorum != QuorumHealthy {
		t.Errorf("expected QuorumHealthy, got %s", state.Quorum)
	}
	if state.ActiveLeaderID != "node-1" {
		t.Errorf("expected initial leader node-1, got %s", state.ActiveLeaderID)
	}

	// Trigger election
	leader, err := mgr.ElectLeader()
	if err != nil {
		t.Fatalf("ElectLeader failed: %v", err)
	}
	if leader == nil || leader.NodeID == "" {
		t.Error("expected valid elected leader")
	}

	// Test Heartbeat
	err = mgr.RecordHeartbeat("node-2", []string{"gateway", "compliancedb", "redteam"})
	if err != nil {
		t.Fatalf("RecordHeartbeat failed: %v", err)
	}
}

func TestCluster_RenderClusterDashboard(t *testing.T) {
	mgr := NewClusterManager("render-cluster")
	_ = mgr.RegisterNode(ClusterNode{
		NodeID:   "primary-node",
		Hostname: "airom.internal",
		Port:     8080,
	})

	state := mgr.GetClusterState()
	dash := RenderClusterDashboard(state)

	if !strings.Contains(dash, "AIROM HIGH-AVAILABILITY CLUSTER TOPOLOGY") {
		t.Error("dashboard missing title banner")
	}
	if !strings.Contains(dash, "primary-node") {
		t.Error("dashboard missing primary-node row")
	}
}

func TestCluster_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	// Register a node via manager directly
	_ = svc.Manager().RegisterNode(ClusterNode{
		NodeID:   "api-node",
		Hostname: "api.internal",
		Port:     9000,
	})

	// GET /api/v1/cluster/state
	resp, err := client.Get(ts.URL + "/api/v1/cluster/state")
	if err != nil {
		t.Fatalf("get state failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 for state, got %d", resp.StatusCode)
	}

	// POST /api/v1/cluster/heartbeat
	hbPayload := map[string]interface{}{
		"node_id":         "api-node",
		"services_active": []string{"all"},
	}
	hbBody, _ := json.Marshal(hbPayload)
	hbResp, err := client.Post(ts.URL+"/api/v1/cluster/heartbeat", "application/json", bytes.NewReader(hbBody))
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	defer func() { _ = hbResp.Body.Close() }()

	if hbResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for heartbeat, got %d", hbResp.StatusCode)
	}

	// Health check
	hResp, err := client.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz failed: %v", err)
	}
	defer func() { _ = hResp.Body.Close() }()

	if hResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for healthz, got %d", hResp.StatusCode)
	}
}
