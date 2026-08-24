package inspector

import (
	"testing"
)

func TestQA_AdversarialUnregisteredAgents(t *testing.T) {
	ins := NewInspector("Root Goal")

	// Message between unregistered ghost agents
	ins.RecordMessage(SwarmMessage{
		MessageID:  "ghost-1",
		SenderID:   "ghost-sender",
		ReceiverID: "ghost-receiver",
		Intent:     "Unregistered agent communication",
		Payload:    "Ghost payload",
	})

	topo := ins.GetTopology()
	if len(topo.Messages) != 1 {
		t.Errorf("expected recorded message from unregistered agent")
	}
}

func TestQA_AdversarialEmptyMessagesAndDrift(t *testing.T) {
	ins := NewInspector("")

	ins.RecordMessage(SwarmMessage{
		MessageID: "empty-1",
	})

	topo := ins.GetTopology()
	if len(topo.Messages) != 1 {
		t.Errorf("expected 1 message")
	}

	d := calculateGoalDrift("", "")
	if d != 0.0 {
		t.Errorf("expected 0.0 drift on empty strings")
	}
}
