package killswitch

import (
	"testing"
)

func TestKillSwitch_TargetedAgentHalt(t *testing.T) {
	mesh := NewMesh()
	mesh.RegisterAgent("agent-1", "cluster-alpha")
	mesh.RegisterAgent("agent-2", "cluster-alpha")

	// Verify both running
	canRun1, _ := mesh.CanExecute("agent-1")
	canRun2, _ := mesh.CanExecute("agent-2")
	if !canRun1 || !canRun2 {
		t.Fatalf("expected both agents operational")
	}

	// Kill agent-1
	mesh.BroadcastKillSignal(KillSignal{
		Scope:    ScopeSingleAgent,
		TargetID: "agent-1",
		Reason:   ReasonRunawayLoop,
	})

	canRun1After, reason := mesh.CanExecute("agent-1")
	canRun2After, _ := mesh.CanExecute("agent-2")

	if canRun1After || reason != ReasonRunawayLoop {
		t.Fatalf("expected agent-1 halted with ReasonRunawayLoop, got canRun=%v reason=%s", canRun1After, reason)
	}
	if !canRun2After {
		t.Fatalf("expected agent-2 to remain operational")
	}
}

func TestKillSwitch_GlobalEmergencyStop(t *testing.T) {
	mesh := NewMesh()
	mesh.RegisterAgent("agent-1", "cluster-a")
	mesh.RegisterAgent("agent-2", "cluster-b")

	mesh.BroadcastKillSignal(KillSignal{
		Scope:  ScopeGlobalMesh,
		Reason: ReasonManualIntervention,
	})

	canRun1, _ := mesh.CanExecute("agent-1")
	canRun2, _ := mesh.CanExecute("agent-2")

	if canRun1 || canRun2 {
		t.Fatalf("expected all nodes halted under global emergency stop")
	}
}
