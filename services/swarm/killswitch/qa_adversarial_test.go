package killswitch

import (
	"testing"
)

func TestQA_AdversarialUnregisteredAgentCheck(t *testing.T) {
	mesh := NewMesh()

	// Unregistered agent without global halt should be allowed
	canRun, _ := mesh.CanExecute("nonexistent_agent")
	if !canRun {
		t.Fatalf("expected unregistered agent to pass default lookup")
	}

	// Under global halt, even unregistered agent must be blocked
	mesh.BroadcastKillSignal(KillSignal{
		Scope:  ScopeGlobalMesh,
		Reason: ReasonManualIntervention,
	})

	canRunGlobal, reason := mesh.CanExecute("nonexistent_agent")
	if canRunGlobal || reason != ReasonManualIntervention {
		t.Fatalf("expected unregistered agent blocked under global halt")
	}
}

func TestQA_AdversarialRepeatedKillSignals(t *testing.T) {
	mesh := NewMesh()
	mesh.RegisterAgent("agent-1", "cluster-1")

	// Fire 10 repeated kill signals
	for i := 0; i < 10; i++ {
		mesh.BroadcastKillSignal(KillSignal{
			Scope:    ScopeSingleAgent,
			TargetID: "agent-1",
			Reason:   ReasonPromptInjection,
		})
	}

	canRun, reason := mesh.CanExecute("agent-1")
	if canRun || reason != ReasonPromptInjection {
		t.Fatalf("expected idempotent halt state")
	}
}
