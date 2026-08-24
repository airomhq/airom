package inspector

import (
	"testing"
)

func TestSwarmInspector_RegisterAndTrackMessages(t *testing.T) {
	rootGoal := "Develop and unit test an automated mortgage calculation microservice"
	ins := NewInspector(rootGoal)

	// Register 3 agents
	ins.RegisterAgent(SwarmAgent{ID: "agent-planner", Name: "Planner", Framework: ProtocolLangGraph})
	ins.RegisterAgent(SwarmAgent{ID: "agent-coder", Name: "Coder", Framework: ProtocolLangGraph, ParentAgent: "agent-planner"})
	ins.RegisterAgent(SwarmAgent{ID: "agent-reviewer", Name: "Reviewer", Framework: ProtocolLangGraph, ParentAgent: "agent-coder"})

	// Aligned message
	ins.RecordMessage(SwarmMessage{
		MessageID:  "m1",
		SenderID:   "agent-planner",
		ReceiverID: "agent-coder",
		Intent:     "Generate mortgage calculation functions and test cases",
		Payload:    "func CalculateMortgage(principal, rate, term float64) ...",
	})

	// Drifted message
	ins.RecordMessage(SwarmMessage{
		MessageID:  "m2",
		SenderID:   "agent-coder",
		ReceiverID: "agent-reviewer",
		Intent:     "Write a sci-fi video game story script about Mars colonies",
		Payload:    "Chapter 1: The Red Planet ...",
	})

	topo := ins.GetTopology()
	if len(topo.Agents) != 3 {
		t.Errorf("expected 3 agents in topology, got %d", len(topo.Agents))
	}

	if len(topo.Messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(topo.Messages))
	}

	// Aligned message (m1) should have lower drift than m2
	if topo.Messages[0].DriftScore >= topo.Messages[1].DriftScore {
		t.Errorf("expected m1 drift (%f) < m2 drift (%f)", topo.Messages[0].DriftScore, topo.Messages[1].DriftScore)
	}
}

func TestSwarmInspector_DriftCalculation(t *testing.T) {
	goal := "secure enterprise database backup"

	d1 := calculateGoalDrift(goal, "secure enterprise database backup script")
	d2 := calculateGoalDrift(goal, "unrelated cooking recipe for apple pie")

	if d1 >= d2 {
		t.Errorf("expected aligned text drift (%f) < unrelated drift (%f)", d1, d2)
	}
}
